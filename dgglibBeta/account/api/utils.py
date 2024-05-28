import re

def get_icon(file_type):
    excel_file_icon = '<i class="fa fa-file-excel-o" style="font-size:30px;color:#3CB371"></i>'
    pdf_file_icon = '<i class="fa fa-file-pdf-o" style="font-size:30px;color:#DC143C" aria-hidden="true"></i>'
    word_file_icon = '<i class="fa fa-file-word-o" style="font-size:30px;color:#00BFFF;" aria-hidden="true"></i>'
    text_icon = '<i class="fa fa-file-text" style="font-size:30px;color:#808080;" aria-hidden="true"></i>'
    zip_file_icon = '<i class="fa fa-file-archive-o"  style="font-size:30px;color:#FFA500" aria-hidden="true"></i>'
    mp3_icon = '<i class="fas fa-music" style="font-size:30px;color:#FF6600"></i>'
    mp4_icon = '<i class="fa fa-play" style="font-size:30px;color:#FF00CC" aria-hidden="true"></i>'
    file_icon = '<i class="fa fa-file" style="font-size:30px;" aria-hidden="true"></i>'
    icon_dict = {
        '.excel':excel_file_icon,
        '.pdf':pdf_file_icon,
        '.word':word_file_icon,
        '.text':text_icon,
        '.zip':zip_file_icon,
        '.mp3':mp3_icon,
        '.file':file_icon,
        '.mp4':mp4_icon,
        '.mkv':mp4_icon,
        '.flv':mp4_icon,
        '.avi':mp4_icon,
        '.wmv':mp4_icon,
        '.m4p':mp4_icon,
        '.m4v':mp4_icon,
        '.mpg':mp4_icon,
        '.mp2':mp4_icon,
        '.mpeg':mp4_icon,
        '.mpe':mp4_icon,
        '.nsv':mp4_icon,
        '.3gp':mp4_icon,
        '.mpv':mp4_icon
    }
    if icon_dict.get(file_type):
        return icon_dict.get(file_type)
    else:
        return ''

def get_real_filesize(size):
    real_size = ""
    if size > 1073741824:
        real_size = str(round(int(size)/1073741824)) + " GB"
    elif size > 1048576:
        real_size = str(round(int(size)/1048576)) + " MB"
    else:
        real_size = str(round(int(size)/1024)) + " KB"
    return real_size

        