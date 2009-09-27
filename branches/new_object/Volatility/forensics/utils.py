import forensics.registry as registry
import forensics.conf
config = forensics.conf.ConfObject()

#pylint: disable-msg=C0111

def load_as(**kwargs):
    base_as = None
    error = AddrSpaceError()
    while 1:
        __debug("Voting round")
        found = False
        for cls in registry.AS_CLASSES.classes:
            __debug("Trying %s " % cls)
            try:
                base_as = cls(base_as, **kwargs)
                __debug("Succeeded instantiating %s" % base_as)
                found = True
                break
            except AssertionError, e:
                __debug("Failed instantiating %s: %s" % (cls.__name__, e), 2) 
                error.append_reason(cls.__name__, e) 
                continue

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found:
            break

    if base_as is None:
        raise error
        
    return base_as

def __debug(msg, level=1):
    if config.DEBUG >= level:
        print msg

class AddrSpaceError(Exception):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        Exception.__init__(self, "No suitable address space maping found")
    
    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = Exception.__str__(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " %s: %s\n" % (k, v)

        return result
