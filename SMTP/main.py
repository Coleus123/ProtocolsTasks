from SMTP.EmailSender import EmailSender

if __name__ == "__main__":
    sender = EmailSender("mail_folder/config.txt")
    sender.send_mail()