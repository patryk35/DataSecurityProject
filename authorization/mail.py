def send_mail(mailjet, email, title, content):
    data = {
        'Messages': [
            {
                "From": {
                    "Email": "pat35@op.pl",
                    "Name": "OD Classes App"
                },
                "To": [
                    {
                        "Email": email,
                        "Name": "User"
                    }
                ],
                "Subject": title,
                "TextPart": content,
                "HTMLPart": ""
            }
        ]
    }
    return mailjet.send.create(data=data)
