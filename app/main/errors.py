from . import page

@page.app_errorhandler
def file_not_found(e):
    return '404', 404