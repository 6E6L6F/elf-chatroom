from os import listdir
class Config:
    SECRET_KEY : str = "Rn5O7XSSFcRvrhsgLM6oEccfMProyjT24K51FoRNmr2IQAcJY8MnUNrgyuivd1BI6bEhX0uOgG7jg9TO4Rs644cqVsLlbCQrYS5RcB1Ev26N3UlN68FX82jadOKlV"
    SQLALCHEMY_DATABASE_URI : str = 'sqlite:///db.sqlite3'
    KEYS = listdir("keys/")
