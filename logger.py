class logger:
    def log(self, msg, isClient=False):
        try:
            color = '\033[92m' # green
            banner = 'Server Says'
            if isClient:
                banner = 'Client Says'
                color = '\033[91m' # red
                
            print '\n{}----{}----\n{}\n\n\033[0m'.format(color, banner, msg)

        except:
            pass