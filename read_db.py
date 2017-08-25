# Author:   Robin Gohmert
# Date:     2016-12-18

import cPickle as pickle

def rename_function(symbol, signature):
    ea = FindBinary(0, SEARCH_DOWN|SEARCH_NEXT, signature)
    if ea == BADADDR:
        #print 'Unable to find signature for "%s"'% symbol
        return False

    #if FindBinary(ea, SEARCH_DOWN|SEARCH_NEXT, signature) == BADADDR:
        #print 'Signature for "%s" is not unique anymore.'% symbol
        #return False

    name = GetFunctionName(ea)
    if not name.startswith('sub_'):
        #print '"%s" has been already renamed to "%s"'% (symbol, name)
        return False

    MakeName(ea, symbol)
    #print 'Found and renamed "%s"'% symbol
    return True

def main():
    db_path = AskFile(0, '*.db', 'Select the database')
    if db_path is None:
        print 'Script has been cancelled.'
        return

    with open(db_path, 'rb') as f:
        signatures = pickle.load(f)

    count = 0
    max_count = len(signatures)
    for index, (symbol, signature) in enumerate(signatures.iteritems(), 1):
        print index, max_count, symbol
        if rename_function(symbol, signature):
            count += 1

    print 'Renamed %s functions!'% count

if __name__ == '__main__':
    main()