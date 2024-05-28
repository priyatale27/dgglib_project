from email_validator import validate_email, EmailNotValidError
def valid_mymail(email):
	try:
		valid = validate_email(email)
		return True
	except EmailNotValidError as e:
		return False


