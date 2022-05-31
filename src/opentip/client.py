import os, urllib.request, urllib.error, hashlib

class OpenTIP:
    def __init__(self, APIKEY:str, no_upload=False, max_upload_size=10 * 1024*1024):
        self.APIKEY = APIKEY
        self.no_upload = no_upload
        self.max_upload_size = max_upload_size
        self.frontend_url = 'https://opentip.kaspersky.com/api/v1/'

    def opentip_get(self, req:str):
        url = self.frontend_url + req
        req = urllib.request.Request(url)
        req.add_header('x-api-key', self.APIKEY)
        with urllib.request.urlopen(req) as f:
            data = f.read().decode('utf-8')
        return data

    def opentip_post(self,req:str,data):
        url = self.frontend_url + req
        req = urllib.request.Request(url,method='POST',data=data)
        req.add_header('x-api-key', self.APIKEY)
        req.add_header('Content-Type', 'application/octet-stream')
        with urllib.request.urlopen(req) as f:
            data = f.read().decode('utf-8')
        return data

    def get_verdict_by_ioc(self, ioc_type:str,ioc_value:str):
        try:
            return self.opentip_get('search/' + ioc_type + '?request=' + ioc_value)
        except urllib.error.HTTPError as e:
            if e.code == 400: # Unknown 
                return None
            else:
                raise

    def scan_file(self,filename):
        # Now, hash the contents of the file
        h = hashlib.new('sha256')
        buf = b''
        try:
            with open(filename, 'rb') as f:
                while True:
                    new_buf = f.read(self.max_upload_size)
                    if len(new_buf) == 0:
                        break
                    buf = new_buf
                    h.update(buf)
        except PermissionError as e:
            return (filename, 'denied')
        except OSError as e:
            return (filename, 'OS error')

        sha = h.hexdigest()
        # Search by hash
        res = self.get_verdict_by_ioc('hash', sha)
        if res is None: # Unknown file
            # Upload the file for analysis
            file_size = os.path.getsize(filename)
            if self.no_upload or ( file_size > self.max_upload_size or file_size == 0 ):
                return (filename, None)
            else:
                try:
                    res = self.opentip_post('scan/file?filename=' + sha, buf)
                    if len(res) == 0:
                        raise RuntimeError(filename)
                    else:
                        return (filename, res)

                except urllib.error.HTTPError as e:
                    raise RuntimeError(_('Error uploading %s') % filename)
        return (filename, res)
        

