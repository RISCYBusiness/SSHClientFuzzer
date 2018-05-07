class logger:
    def log(self, msg, isClient=False):
        try:
            if isClient:
                print '----Client Says----\n{}'.format(msg)
            else:
                print '----Sever Sends----\n{}'.format(msg)
        except:
            pass