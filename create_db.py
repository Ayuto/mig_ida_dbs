# Author:   Robin Gohmert
# Date:     2016-12-18

import idaapi
import cPickle as pickle

MAX_EA = MaxEA()
MAX_SIG_LENGTH = 5000

def get_imported_functions():
    result = []

    def imp_cb(ea, name, ord):
        result.append(ea)
        return True

    nimps = idaapi.get_import_module_qty()

    for i in xrange(nimps):
        name = idaapi.get_import_module_name(i)
        if name is None:
            print 'Failed to get import module name for #%i' % i
            continue

        idaapi.enum_import_names(i, imp_cb)

    return result

IMPORTED_FUNCTIONS = get_imported_functions()

def create_signature(ea, max_length):
    # This function is based on this:
    # https://github.com/alliedmodders/sourcemod/blob/master/tools/ida_scripts/makesig.idc
    func_start = ea
    address = ea
    signature = ''

    while address != BADADDR and len(signature) < max_length:
        info = DecodeInstruction(address)
        if not info:
            #Warning("Something went terribly wrong D:");
            return None

        if info.size == 1 and (info.Operands[0].type in (o_near, o_far)):
            signature += '%02X %s'% (Byte(address), print_wildcards(get_dt_size(info.Operands[0].dtyp)))
        else:
            # unknown, just wildcard addresses
            i = 0
            while i < info.size:
                loc = address + i;
                if GetFixupTgtType(loc) == FIXUP_OFF32:
                    signature += print_wildcards(4)
                    i = i + 4;
                else:
                    signature += '%02X '% Byte(loc)
                    i += 1

        if is_good_sig(func_start, signature):
            return signature

        last_loc = address + info.size;
        address = NextHead(address, MAX_EA);
        if address - last_loc > 32:
            return None

        # Add unhandled bytes (probably alignment)
        if last_loc < address:
            while last_loc < address:
                signature += '%02X '% Byte(last_loc)
                last_loc += 1

            if is_good_sig(func_start, signature):
                return signature

    return None

def get_dt_size(dtyp):
    if dtyp == dt_byte:
        return 1
    if dtyp == dt_word:
        return 2
    if dtyp == dt_dword:
        return 4
    if dtyp == dt_float:
        return 4
    if dtyp == dt_double:
        return 8

    Warning('Unknown type size (%d)', dtyp);
    return -1

def print_wildcards(count):
    return '? ' * count

SEARCH_DOWN_NEXT = SEARCH_DOWN|SEARCH_NEXT

def is_good_sig(func_start, sig):
    return (FindBinary(0, SEARCH_DOWN_NEXT, sig) == func_start
        and FindBinary(func_start, SEARCH_DOWN_NEXT, sig) == BADADDR)

def main():
    db_path = AskFile(1, '*.db', 'Select a destination for the database')
    if db_path is None:
        print 'Script has been cancelled.'
        return

    signatures = {}
    for index, ea in enumerate(tuple(Functions()), 1):
        if ea in IMPORTED_FUNCTIONS:
            continue

        name = GetFunctionName(ea)
        if name.startswith('sub_'):
            continue

        print index, name
        signature = create_signature(ea, MAX_SIG_LENGTH)
        if signature is None:
            print 'Failed to create a signature for "%s"'% name
            continue

        signatures[name] = signature

    print 'Found signatures for %s functions. Saving DB...'% len(signatures)
    with open(db_path, 'wb') as f:
        pickle.dump(signatures, f)

    print 'Saved!'

if __name__ == '__main__':
    main()