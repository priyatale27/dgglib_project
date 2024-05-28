
# module used
from datetime import datetime, date
import mysql.connector
from configparser import ConfigParser
import sys
import logging
import os

logger = logging.getLogger(__name__)
f_handler = logging.FileHandler('error.log')
f_handler.setLevel(logging.ERROR)
f_format = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger.addHandler(f_handler)


# database configuration
config = ConfigParser()
config.read('script_config.ini')

try:
    mydb = mysql.connector.connect(
        host=config['DATABASE']['Host'],
        user=config['DATABASE']['User'],
        passwd=config['DATABASE']['Password'],
        port=int(config['DATABASE']['Port']),
        database=config['DATABASE']['Database']
    )
except Exception as e:
    logger.error(e)
    sys.exit()


#######################################################################################################

def main_init():
    
    today = datetime.now().date()
    c = mydb.cursor(buffered=True)
    c.execute(
        'select id,created_date,file_name from account_deletedfilefolder;')
    all_files = c.fetchall()
    for item in all_files:
        item_id = item[0]
        created_time = item[1].date()
        file_name = item[2]
        if today > created_time:
            print(item_id)
            if((today - created_time).days)==30:
                if '/' in str(os):
                    full_path = os.path.join(settings.MEDIA_ROOT,str(file_name))
                    os.remove(full_path)
                else:
                    trash_path = file_name
                    os.remove(str(trash_path))
                e = mydb.cursor(buffered=True)
                e.execute('DELETE from account_deletedfilefolder where id="%s";',[item_id])
                mydb.commit()
                
                
        
    c.close()
    


# Execute the script
if __name__ == "__main__":
    main_init()
