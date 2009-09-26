import forensics.registry as registry

def load_as(opts):
    base_as = None
    error = AddrSpaceError()
    while 1:
        # print "Voting round"
        found = False
        for cls in  registry.AS_CLASSES.classes:
            # print "Trying %s " % cls
            try:
                base_as = cls(base_as, opts.__dict__)
                # print "Succeeded instantiating %s" % base_as
                found = True
                break
            except Exception, e:
                print "%r: %s" % (e,e)
                error.append_reason(cls.__name__, e) 
                continue

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found:
            break

    if base_as is None:
        raise error
        
    return base_as

class AddrSpaceError(Exception):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        Exception.__init__(self, "No suitable address space maping found")
    
    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = Exception.__str__(self) + "\nTried to open image as:\n"
        for k,v in self.reasons:
            result += " %s: %s\n" % (k,v)

        return result
