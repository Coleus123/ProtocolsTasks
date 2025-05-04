import struct
import time
import traceback

RECORD_TYPES = {
    1: 'A',
    28: 'AAAA',
    2: 'NS',
    12: 'PTR'
}


def parse_dns_response(data):
    """Парсит DNS-запрос и извлекает имя, тип и transaction ID"""
    tid = struct.unpack("!H", data[:2])[0]
    qname = []
    idx = 12
    while True:
        length = data[idx]
        if length == 0:
            idx += 1
            break
        qname.append(data[idx + 1:idx + 1 + length].decode())
        idx += 1 + length
    query_name = '.'.join(qname)
    qtype = struct.unpack("!H", data[idx:idx + 2])[0]
    return query_name, qtype, tid


def encode_name(name):
    """Преобразует доменное имя в DNS-формат (байты с длинами)"""
    parts = name.split('.')
    result = b''
    for part in parts:
        result += bytes([len(part)]) + part.encode()
    result += b'\x00'
    return result


def read_name(data, offset):
    """Читает доменное имя из DNS-сообщения (с учётом сжатия)"""
    labels = []
    jumped = False
    start_offset = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # Сжатое имя
            if not jumped:
                start_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
        elif length == 0:
            offset += 1
            break
        else:
            labels.append(data[offset + 1:offset + 1 + length].decode())
            offset += 1 + length

    name = '.'.join(labels)
    return name, (start_offset if jumped else offset)


def extract_records(data):
    """Извлекает записи из ответа DNS (answer, authority, additional)"""
    records = []
    header = struct.unpack("!6H", data[:12])
    qdcount, ancount, nscount, arcount = header[2], header[3], header[4], header[5]
    offset = 12
    for _ in range(qdcount):
        _, offset = read_name(data, offset)
        offset += 4

    def parse_rr(offset, count):
        rrs = []
        for _ in range(count):
            try:
                name, offset = read_name(data, offset)
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
                offset += 10
                rdata_raw = data[offset:offset + rdlength]

                if rtype in RECORD_TYPES:
                    if rtype == 1:
                        rdata = ".".join(str(b) for b in rdata_raw)
                    elif rtype == 28:
                        rdata = ":".join(format(struct.unpack("!H", rdata_raw[i:i + 2])[0], 'x') for i in range(0, 16, 2))
                    elif rtype in (2, 12):
                        rdata, _ = read_name(data, offset)
                    else:
                        rdata = rdata_raw.hex()
                    rrs.append({
                        'name': name,
                        'type': rtype,
                        'ttl': ttl,
                        'data': rdata
                    })
                offset += rdlength
            except Exception as e:
                print(f"[ERROR] Ошибка при парсинге RR: {e}")
                traceback.print_exc()
        return rrs, offset

    answers, offset = parse_rr(offset, ancount)
    authorities, offset = parse_rr(offset, nscount)
    additionals, offset = parse_rr(offset, arcount)
    records.extend(answers + authorities + additionals)
    return records


def build_dns_response(tid, query_data, records):
    """Собирает DNS-ответ на основе кэша"""
    header = struct.pack("!HHHHHH",
                         tid,
                         0x8180,
                         1,
                         len(records),
                         0,
                         0)
    question_start = 12
    while query_data[question_start] != 0:
        question_start += query_data[question_start] + 1
    question_end = question_start + 5
    question = query_data[12:question_end]
    answers = b''
    for rec in records:
        name = encode_name(rec['name'])
        rtype = int(rec['type'])
        rclass = 1
        ttl = max(0, int(rec['ttl'] - (time.time() - rec['timestamp'])))
        if ttl == 0:
            continue
        if rtype == 1:
            rdata = bytes(map(int, rec['data'].split('.')))
        elif rtype == 28:
            parts = rec['data'].split(':')
            full = []
            for part in parts:
                if part == '':
                    full += [0] * (8 - len([p for p in parts if p]))
                else:
                    full.append(int(part, 16))
            rdata = b''.join(struct.pack("!H", p) for p in full)
        elif rtype in (2, 12):
            rdata = encode_name(rec['data'])
        else:
            continue
        rdlength = len(rdata)
        answers += name + struct.pack("!HHIH", rtype, rclass, ttl, rdlength) + rdata
    return header + question + answers