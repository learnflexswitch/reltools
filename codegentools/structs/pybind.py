"""
Copyright 2015, Rob Shakir (rjs@jive.com, rjs@rob.sh)

This project has been supported by:
          * Jive Communications, Inc.
          * BT plc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import optparse
import sys
import re
import string
import decimal
import copy
import os
import subprocess
from bitarray import bitarray
import json

from pyang import plugin
from pyang import statements

DEBUG = True
if DEBUG:
    import pprint
    pp = pprint.PrettyPrinter(indent=2)


# for each structure there may be a 'list' key that should be identified
# for purposes of a DB
LIST_KEY_STR = '`SNAPROUTE: "KEY", '

# YANG is quite flexible in terms of what it allows as input to a boolean
# value, this map is used to provide a mapping of these values to the python
# True and False boolean instances.
class_bool_map = {
  'false':  False,
  'False':  False,
  'true':    True,
  'True':    True,
}

class_map = {
  # this map is dynamically built upon but defines how we take
  # a YANG type  and translate it into a native Python class
  # along with other attributes that are required for this mapping.
  #
  # key:                the name of the YANG type
  # native_type:        the GO type that is used to support this
  #                     YANG type natively.
  # map (optional):     a map to take input values and translate them
  #                     into valid values of the type.
  # base_type:          whether the class can be used as class(*args, **kwargs)
  #                     in Python, or whether it is a derived class (such as is
  #                     created based on a typedef, or for types that cannot be
  #                     supported natively, such as enumeration, or a string
  #                     with a restriction placed on it)
  # quote_arg (opt):    whether the argument to this class' __init__ needs to be
  #                     quoted (e.g., str("hello")) in the code that is output.
  # pytype (opt):       A reference to the actual type that is used, this is
  #                     used where we infer types, such as for an input value to
  #                     a union since we need to actually compare the value
  #                     against the __init__ method and see whether it works.
  # parent_type (opt):  for "derived" types, then we store what the enclosed
  #                     type is such that we can create instances where required
  #                     e.g., a restricted string will have a parent_type of a
  #                     string. this can be a list if the type is a union.
  # restriction ...:    where the type is a restricted type, then the class_map
  # (optional)          dict entry can store more information about the type of
  #                     restriction. this is generally used when we need to
  #                     re-initialise an instance of the class, such as in the
  #                     setter methods of containers.
  # Other types may add their own types to this dictionary that have meaning
  # only for themselves. For example, a ReferenceType can add the path that it
  # references, and whether the require-instance keyword was set or not.
  'boolean':          {"native_type": "bool", "map": class_bool_map,
                          "base_type": True, "quote_arg": True},
  'binary':           {"native_type": "bitarray", "base_type": True,
                          "quote_arg": True},
  'uint8':            {"native_type": "uint8", "base_type": True, "max": "^uint8(0)"},
  'uint16':           {"native_type": "uint16", "base_type": True, "max": "^uint16(0)"},
  'uint32':           {"native_type": "uint32", "base_type": True, "max": "^uint32(0)"},
  'uint64':           {"native_type": "uint64", "base_type": True, "max": "^uint64(0)"},
  'string':           {"native_type": "string", "base_type": True,
                          "quote_arg": True},
  'decimal64':        {"native_type": "float64", "base_type": True},
  'empty':            {"native_type": "bool", "map": class_bool_map,
                          "base_type": True, "quote_arg": True},
  'int8':             {"native_type": "int8", "base_type": True, "max": "^int8(0)"},
  'int16':            {"native_type": "int16", "base_type": True, "max": "^int16(0)"},
  'int32':            {"native_type": "int32", "base_type": True, "max": "^uint32(0)"},
  'int64':            {"native_type": "int64", "base_type": True, "max": "^uint64(0)"},
}

# We have a set of types which support "range" statements in RFC6020. This
# list determins types that should be allowed to have a "range" argument.
INT_RANGE_TYPES = ["uint8", "uint16", "uint32", "uint64",
                    "int8", "int16", "int32", "int64"]


# Words that could turn up in YANG definition files that are actually
# reserved names in Python, such as being builtin types. This list is
# not complete, but will probably continue to grow.
reserved_name = ["list", "str", "int", "global", "decimal", "float",
                  "as", "if", "else", "elsif", "map", "set", "class",
                  "from", "import", "pass", "return", "is", "exec",
                  "pop", "insert", "remove", "add", "delete", "local",
                  "get", "default", "yang_name"]


ENABLE_CAMEL_CASE = True
OBJECTS_NAME = 'objects'
srBase = os.environ.get('SR_CODE_BASE', None)
OBJECTS_PATH_LIST = [srBase + "/generated/src/models/objects/"]
CODE_GENERATION_PATH = srBase + "/generated/src/models/objects/"
GENERATED_FILES_LIST = srBase + "/reltools/codegentools/._genInfo/generatedGoFiles.txt"
gYangObjInfo = None
gOwnersInfo  = None

def safe_name(arg):
    """
      Make a leaf or container name safe for use in Python.
    """
    #print "safe_name", arg
    if ENABLE_CAMEL_CASE:
        l = arg.split('-')
        if len(l) > 0:
            arg = "".join([x[0].upper() + x[1:] for x in l if x != ''])
        l = arg.split('.')
        if len(l) > 0:
            arg = "".join([x[0].upper() + x[1:] for x in l if x != ''])
        l = arg.split(':')
        if len(l) > 0:
            arg = "".join([x[0].upper() + x[1:] for x in l if x != ''])
        l = arg.split('_')
        if len(l) > 0:
            arg = "".join([x[0].upper() + x[1:] for x in l if x != ''])
        l = arg.split('/')
        if len(l) > 0:
            arg = "".join([x[0].upper() + x[1:] for x in l if x != ''])

    else:
        arg = arg.replace("-", "_")
        arg = arg.replace(".", "_")
        arg = arg.replace(":", "_")

    if arg in reserved_name:
        arg += "_"

    # store the unsafe->original version mapping
    # so that we can retrieve it when get() is called.
    return arg


gDryRun =  False
# Base machinery to support operation as a plugin to pyang.
def pyang_plugin_init():
    plugin.register_plugin(BTPyGOClass())

class BTPyGOClass(plugin.PyangPlugin):
    def add_output_format(self, fmts):
            # Add the 'pybind' output format to pyang.
        self.multiple_modules = True
        fmts['pybind'] = self
        self.owner    = None

    def emit(self, ctx, modules, fd):
        # When called, call the build_pyangbind function.
        name = fd.name.split('.')[0]
        fdDict = {"struct" : fd}

        modelFileName  = fd.name.strip('.tmp')
        #serializerName = modelFileName.strip('.go') + '_serializer.go'
        build_pybind(ctx, modules, fdDict)

        with open(GENERATED_FILES_LIST, 'a+') as fp:
            fp.write(modelFileName + '\n')
            #fp.write(serializerName+ '\n')

        objsData = srBase+ '/snaproute/src/models/objects/'+'genObjectConfig.json' 
        with open(objsData, 'w+') as fp:
            json.dump(gYangObjInfo, fp,  indent=2)

        #actionsData = srBase+ '/snaproute/src/models/actions/'+'genObjectAction.json' 
        #with open(actionsData, 'w+') as fp:
        #    json.dump(gYangObjInfo, fp,  indent=2)

        #for f in fdDict.values():
        #    f.close()
        #    executeGoFmtCommand(f, ['gofmt -w %s' % f.name])


    def add_opts(self, optparser):
        # Add pyangbind specific operations to pyang. These are documented in the
        # options, but are essentially divided into three sets.
        #   * xpathhelper - How pyangbind should deal with xpath expressions. This
        #     module is documented in lib/xpathhelper and describes how support
        #     registration, updates, and retrieval of xpaths.
        #   * class output - whether a single file should be created, or whether a
        #     hierarchy of python modules should be created. The latter is
        #     preferable when one has large trees being compiled.
        #   * extensions - support for YANG extensions that pyangbind should look
        #     for, and add as a dictionary with each element.
        optlist = [
                    optparse.make_option("--use-xpathhelper",
                                         dest="use_xpathhelper",
                                         action="store_true",
                                         help="""Use the xpathhelper module to
                                                 resolve leafrefs"""),
                    optparse.make_option("--split-class-dir",
                                         metavar="DIR",
                                         dest="split_class_dir",
                                         help="""Split the code output into
                                                 multiple directories"""),
                    optparse.make_option("--pybind-class-dir",
                                          metavar="DIR",
                                          dest="pybind_class_dir",
                                          help="""Path in which the pyangbind
                                                  'lib' directionary can be found
                                                  - assumed to be the local
                                                  directory if this option
                                                  is not specified"""),
                    optparse.make_option("--interesting-extension",
                                        metavar="EXTENSION-MODULE",
                                        default=[],
                                        action="append",
                                        type=str,
                                        dest="pybind_interested_exts",
                                        help="""A set of extensions that
                                                are interesting and should be
                                                stored with the class. They
                                                can be accessed through the
                                                "extension_dict()" argument.
                                                Multiple arguments can be
                                                specified."""),
                    optparse.make_option("--use-extmethods",
                                        dest="use_extmethods",
                                        action="store_true",
                                        help="""Allow a path-keyed dictionary
                                                to be used to specify methods
                                                related to a particular class"""),
                    optparse.make_option("--specific-object",
                                        dest="specific_object",
                                        action="store",
                                        help="""Generate Gobindings only for a specific object"""),
                    optparse.make_option("--owner",
                                        dest="owner",
                                        action="store",
                                        help="""Owner daemon responsible for this model"""),
                  ]
        g = optparser.add_option_group("pyangbind output specific options")
        g.add_options(optlist)


# Core function to build the pyangbind output - starting with building the
# dependencies - and then working through the instantiated tree that pyang has
# already parsed.
def build_pybind(ctx, modules, fdDict):

    # Restrict the output of the plugin to only the modules that are supplied
    # to pyang. More modules are parsed by pyangbind to resolve typedefs and
    # identities.
    module_d = {}
    for mod in modules:
        module_d[mod.arg] = mod
    pyang_called_modules = module_d.keys()

    # Bail if there are pyang errors, since this certainly means that the
    # pyangbind output will fail - unless these are solely due to imports that
    # we provided but then unused.
    if len(ctx.errors):
        for e in ctx.errors:
            if not e[1] == "UNUSED_IMPORT":
                sys.stderr.write("FATAL: pyangbind cannot build module that pyang" + \
                  " has found errors with.\n")
                sys.exit(127)

    # Build the common set of imports that all pyangbind files needs
    ctx.pybind_common_hdr = ""

    for fd in fdDict.values():
        fd.write(ctx.pybind_common_hdr)

    # Determine all modules, and submodules that are needed, along with the
    # prefix that is used for it. We need to ensure that we understand all of the
    # prefixes that might be used to reference an identity or a typedef.
    all_mods = []
    for module in modules:
        local_module_prefix = module.search_one('prefix')
        if local_module_prefix is None:
            local_module_prefix = module.search_one('belongs-to').search_one('prefix')
            if local_module_prefix is None:
                raise AttributeError("A module (%s) must have a prefix or parent " + \
                  "module")
            local_module_prefix = local_module_prefix.arg
        else:
            local_module_prefix = local_module_prefix.arg
        mods = [(local_module_prefix,module)]
        # 'include' statements specify the submodules of the existing module - which
        # also need to be parsed.
        for i in module.search('include'):
            subm = ctx.get_module(i.arg)
            if subm is not None:
                mods.append((local_module_prefix, subm))
        # 'import' statements specify the other modules that this module will
        # reference.
        for j in module.search('import'):
            mod = ctx.get_module(j.arg)
            if mod is not None:
                imported_module_prefix = j.search_one('prefix').arg
                mods.append((imported_module_prefix, mod))
                modules.append(mod)
        all_mods.extend(mods)

    # remove duplicates from the list (same module and prefix)
    new_all_mods = []
    for mod in all_mods:
        if not mod in new_all_mods:
            new_all_mods.append(mod)
    all_mods = new_all_mods

    # Build a list of the 'typedef' and 'identity' statements that are included
    # in the modules supplied.
    defn = {}
    for defnt in ['typedef', 'identity']:
        defn[defnt] = {}
        for m in all_mods:
            t = find_definitions(defnt, ctx, m[1], m[0])
            for k in t:
                if not k in defn[defnt]:
                    defn[defnt][k] = t[k]


# this is temproary and specific to openconfig yang models.
    # the go packe name will be based on the name of the module
    # which contains either 1 or two names as seperated by "-"
    '''
    pkgname = "openconfig_unknownpkg"
    for modname in pyang_called_modules:
      tmp = modname.split('-')
      if len(tmp) == 2:
        pkgname = tmp[0] + "_" + tmp[1]
        break
    ctx.pybind_common_hdr = "package %s\n\n" %(pkgname,)
    '''

    #for modname in pyang_called_modules:
    #  print 'found module', modname

    ctx.pybind_common_hdr = "package %s\n\n" % (OBJECTS_NAME)
    for fd in fdDict.values():
        fd.write(ctx.pybind_common_hdr)


    #fdDict["func"].write("import (\n")
    #fdDict["func"].write("""\t \"encoding/json\"\n
    #\t\"fmt\"\n
    #)\n""")

    #fdDict["func"].write("""type ConfigObj interface {
    #     UnmarshalObject(data []byte) (ConfigObj, error)
    #    }\n""")


    # Build the identities and typedefs (these are added to the class_map which
    # is globally referenced).
    build_identities(ctx, defn['identity'])
    build_typedefs(ctx, defn['typedef'])

    # create the enumerations
    #CreateEnumerations(fdDict["enums"])

    # create the structs and functions associated with the structs
    CreateGoStructAndFunc(ctx, fdDict, module_d, pyang_called_modules)



def CreateGoStructAndFunc(ctx, fdDict, module_d, pyang_called_modules):
    # Iterate through the tree which pyang has built, solely for the modules
    # that pyang was asked to build
    for modname in pyang_called_modules:

        module = module_d[modname]
        mods = [module]
        for i in module.search('include'):
            subm = ctx.get_module(i.arg)
            if subm is not None:
                mods.append(subm)
        for m in mods:
            children = [ch for ch in module.i_children
                        if ch.keyword in statements.data_definition_keywords]

            get_children(ctx, fdDict, children, m, m)

enumerationDict = {}
def CreateEnumerations(fd):
    # Build enumerations
    fd.write("""//enumerations\n""")
    fd.write("""var (\n""")
    for k, v in class_map.iteritems():
        if "restriction_type" in v and \
                v["restriction_type"] == "dict_key":
            i = 0
            for e, ev in v["restriction_argument"].iteritems():
                value = i
                if len(ev) > 0:
                    value = ev["value"]

                name = k + "_" + e
                name = safe_name(name)
                # save off the enum
                enumerationDict.update({name:value})
                i = value
                i += 1

                fd.write("\t%s = %d\n" % (name, value))
    fd.write(""")\n""")

def build_identities(ctx, defnd):
    # Build dicionaries which determine how identities work. Essentially, an
    # identity is modelled such that it is a dictionary where the keys of that
    # dictionary are the valid values for an identityref.
    unresolved_idc = {}
    for i in defnd:
        unresolved_idc[i] = 0
    unresolved_ids = defnd.keys()
    error_ids = []
    identity_d = {}

    # The order of an identity being built is important. Find those identities
    # that either have no "base" statement, or have a known base statement, and
    # queue these to be processed first.
    while len(unresolved_ids):
        ident = unresolved_ids.pop(0)
        base = defnd[ident].search_one('base')
        reprocess = False
        if base is None and not unicode(ident) in identity_d:
            identity_d[unicode(ident)] = {}
        else:
            # the identity has a base, so we need to check whether it
            # exists already
            if unicode(base.arg) in identity_d:
                base_id = unicode(base.arg)
                # if it did, then we can now define the value - we want to
                # define it as both the resolved value (i.e., with the prefix)
                # and the unresolved value.
                if ":" in ident:
                    prefix,value = ident.split(":")
                    prefix,value = unicode(prefix),unicode(value)
                    if not value in identity_d[base_id]:
                        identity_d[base_id][value] = {}
                    if not value in identity_d:
                        identity_d[value] = {}
                    # check whether the base existed with the prefix that was
                    # used for this value too, as long as the base_id is not
                    # already resolved
                    if not ":" in base_id:
                        resolved_base = unicode("%s:%s" % (prefix, base_id))
                        if not resolved_base in identity_d:
                            reprocess = True
                        else:
                            identity_d[resolved_base][ident] = {}
                            identity_d[resolved_base][value] = {}
                if not ident in identity_d[base_id]:
                    identity_d[base_id][ident] = {}
                if not ident in identity_d:
                    identity_d[ident] = {}
            else:
                reprocess = True

            if reprocess:
                # Fall-out from the loop of resolving the identity. If we've looped
                # around many times, we can't find a base for the identity, which means
                # it is invalid.
                if unresolved_idc[ident] > 1000:
                    sys.stderr.write("could not find a match for %s base: %s\n" % \
                      (ident, base.arg))
                    error_ids.append(ident)
                else:
                    unresolved_ids.append(ident)
                    unresolved_idc[ident] += 1


    # Remove those identities that do not have any members. This would remove
    # identities that are solely bases, but have no other members. However, this
    # is a problem if particular modules are compiled.
    #for potential_identity in identity_d.keys():
    #  if len(identity_d[potential_identity]) == 0:
    #    del identity_d[potential_identity]

    if error_ids:
        raise TypeError("could not resolve identities %s" % error_ids)

    # Add entries to the class_map such that this identity can be referenced by
    # elements that use this identity ref.
    for i in identity_d:
        '''
        id_type = {"native_type": """RestrictedClassType(base_type=unicode, """ + \
                                  """restriction_type="dict_key", """ + \
                                  """restriction_arg=%s,)""" % identity_d[i], \
                    "restriction_argument": identity_d[i], \
                    "restriction_type": "dict_key",
                    "parent_type": "string",
                    "base_type": False,}
        '''
        id_type = {"native_type": """string""",
                    "restriction_argument": identity_d[i], \
                    "restriction_type": "dict_key",
                    "parent_type": "string",
                    "base_type": False,}
        class_map[i] = id_type

def build_typedefs(ctx, defnd):
    # Build the type definitions that are specified within a model. Since
    # typedefs are essentially derived from existing types, order of processing
    # is important - we need to go through and build the types in order where
    # they have a known 'type'.
    unresolved_tc = {}
    for i in defnd:
        unresolved_tc[i] = 0
    unresolved_t = defnd.keys()
    error_ids = []
    known_types = class_map.keys()
    known_types.append('enumeration')
    known_types.append('leafref')
    process_typedefs_ordered = []
    while len(unresolved_t):

        t = unresolved_t.pop(0)
        base_t = defnd[t].search_one('type')
        if base_t.arg == "union":
            subtypes = [i for i in base_t.search('type')]
        elif base_t.arg == "identityref":
            subtypes = [base_t.search_one('base'),]
        else:
            subtypes = [base_t,]


        any_unknown = False
        for i in subtypes:
            if not i.arg in known_types:
                any_unknown=True
        if not any_unknown:
            process_typedefs_ordered.append((t, defnd[t]))
            known_types.append(t)
        else:
            unresolved_tc[t] += 1
            if unresolved_tc[t] > 1000:
                # Take a similar approach to the resolution of identities. If we have a
                # typedef that has a type in it that is not found after many iterations
                # then we should bail.
                error_ids.append(t)
                sys.stderr.write("could not find a match for %s type -> %s\n" % \
                  (t,[i.arg for i in subtypes]))
            else:
                unresolved_t.append(t)

    if error_ids:
        raise TypeError("could not resolve typedefs %s" % error_ids)

    # Process the types that we built above.
    for i_tuple in process_typedefs_ordered:
        item = i_tuple[1]
        type_name = i_tuple[0]
        mapped_type = False
        restricted_arg = False
        # Copy the class_map entry - this is done so that we do not alter the
        # existing instance in memory as we add to it.
        cls,elemtype = copy.deepcopy(build_elemtype(ctx, item.search_one('type')))
        known_types = class_map.keys()
        # Enumeration is a native type, but is not natively supported
        # in the class_map, and hence we append it here.
        known_types.append("enumeration")
        known_types.append("leafref")

        # Don't allow duplicate definitions of types
        if type_name in known_types:
            raise TypeError("Duplicate definition of %s" % type_name)
        default_stmt = item.search_one('default')

        #print 'build typedefs', item, type_name, default_stmt, elemtype
        # 'elemtype' is a list when the type includes a union, so we need to go
        # through and build a type definition that supports multiple types.
        if not isinstance(elemtype,list):
            restricted = False
            # Map the original type to the new type, parsing the additional arguments
            # that may be specified, for example, a new default, a pattern that must
            # be matched, or a length (stored in the restriction_argument, and
            # restriction_type class_map variables).
            class_map[type_name] = {"base_type": False,}
            class_map[type_name]["native_type"] = elemtype["native_type"]
            if "parent_type" in elemtype:
                class_map[type_name]["parent_type"] = elemtype["parent_type"]
            else:
                yang_type = item.search_one('type').arg
                if not yang_type in known_types:
                    raise TypeError("typedef specified a native type that was not " +
                                      "supported")
                class_map[type_name]["parent_type"] = yang_type
            if default_stmt is not None:
                class_map[type_name]["default"] = default_stmt.arg
            if "referenced_path" in elemtype:
                class_map[type_name]["referenced_path"] = elemtype["referenced_path"]
                class_map[type_name]["class_override"] = "leafref"
            if "require_instance" in elemtype:
                class_map[type_name]["require_instance"] = elemtype["require_instance"]
            if "restriction_type" in elemtype:
                class_map[type_name]["restriction_type"] = \
                                                      elemtype["restriction_type"]
                class_map[type_name]["restriction_argument"] = \
                                                      elemtype["restriction_argument"]
            if "quote_arg" in elemtype:
                class_map[type_name]["quote_arg"] = elemtype["quote_arg"]
            if "restriction_dict" in elemtype:
                class_map[type_name]["restriction_dict"] = elemtype["restriction_dict"]
        else:
            # Handle a typedef that is a union - extended the class_map arguments
            # to be a list that is parsed by the relevant dynamic type generation
            # function.
            native_type = []
            parent_type = []
            default = False if default_stmt is None else default_stmt.arg
            for i in elemtype:
                if isinstance(i[1]["native_type"], list):
                    native_type.extend(i[1]["native_type"])
                else:
                    native_type.append(i[1]["native_type"])
                if i[1]["yang_type"] in known_types:
                    parent_type.append(i[1]["yang_type"])
                else:
                    msg = "typedef in a union specified a native type that was not"
                    msg += "supported (%s in %s)" % (i[1]["yang_type"], item.arg)
                    raise TypeError(msg)
                if "default" in i[1] and not default:
                    # When multiple 'default' values are specified within a union that
                    # is within a typedef, then pyangbind will choose the first one.
                    q = True if "quote_arg" in i[1] else False
                    default = (i[1]["default"], q)
            class_map[type_name] = {"native_type": native_type, "base_type": False,
                                    "parent_type": parent_type,}
            if default:
                class_map[type_name]["default"] = default[0]
                class_map[type_name]["quote_default"] = default[1]

def GetParentChildrenLeafs(ctx, i_module, parent, parentChildrenLeaf=None):

    def buildParentLeafs(ctx, ch, childLeaf, parentChildrenLeaf):
        if ch.keyword in ('leaf', 'leaf-list'):
            childLeaf += 1
            if ch.arg not in parentChildrenLeaf:
                t = ch.search_one('type')
                des = ch.search_one('description')
                et = None
                if t is not None:
                    et = build_elemtype(ctx, t)
                    # print "decode child:", ch.arg, et
                isKey = False
                # print ch.__dict__
                if hasattr(ch, "i_is_key"):
                    isKey = ch.i_is_key
                parentChildrenLeaf.update({ch.arg: (et, isKey, des.arg)})


    if parent.parent not in ({}, None, ''):
        childLeaf = 0
        for ch in parent.i_children:
            if ch.arg.lower() == 'config':
                for config_ch in ch.i_children:
                    buildParentLeafs(ctx, config_ch, childLeaf, parentChildrenLeaf)
            elif ch.keyword == 'choice':
                for choice_ch in ch.i_children:
                    # these are case statements
                    for case_ch in choice_ch.i_children:
                        buildParentLeafs(ctx, ch, childLeaf, parentChildrenLeaf)
            else:
                buildParentLeafs(ctx, ch, childLeaf, parentChildrenLeaf)

        if childLeaf == len(parent.i_children):
            x = [ch.arg for ch in parent.i_children if ch.keyword in ('leaf', 'leaf-list', 'choice')]
            for arg in x:
                parentChildrenLeaf.pop(arg)
            #print "found all children are leafs removing from childrenStore", x
        #else:
            #x = [ch.arg for ch in parent.i_children if ch.keyword in ('leaf', 'leaf-list')]
            #if x:
            #  print "mix of leaf and not", [ch.arg for ch in parent.i_children if ch.keyword in ('leaf', 'leaf-list')]
        GetParentChildrenLeafs(ctx, parent.i_module, parent.parent, parentChildrenLeaf)




def find_definitions(defn, ctx, module, prefix):
    # Find the statements within a module that map to a particular type of
    # statement, for instance - find typedefs, or identities, and reutrn them
    # as a dictionary to the calling function.
    mod = ctx.get_module(module.arg)
    if mod is None:
        raise AttributeError("expected to be able to find module %s, " % \
                            (module.arg) + "but could not")
    type_definitions = {}
    for i in mod.search(defn):
        if i.arg in type_definitions:
            sys.stderr.write("WARNING: duplicate definition of %s" % i.arg)
        else:
            type_definitions["%s:%s" % (prefix, i.arg)] = i
            type_definitions[i.arg] = i
    return type_definitions

def get_children(ctx, fdDict, i_children, module, parent, path=str(), \
                 parent_cfg=True, choice=False):
    # Iterative function that is called for all elements that have childen
    # data nodes in the tree. This function resolves those nodes into the
    # relevant leaf, or container/list configuration and outputs the python
    # code that corresponds to it to the relevant file. parent_cfg is used to
    # ensure that where a parent container was set to config false, this is
    # inherited by all elements below it; and choice is used to store whether
    # these leaves are within a choice or not.
    used_types,elements = [],[]
    choices = False

    if parent_cfg:
        # The first time we find a container that has config false set on it
        # then we need to hand this down the tree - we don't need to look if
        # parent_cfg has already been set to False as we need to inherit.
        parent_config = parent.search_one('config')
        if parent_config is not None:
            parent_config = parent_config.arg
            if parent_config.upper() == "FALSE":
                # this container is config false
                parent_cfg = False

    # When we are asked to split the classes into modules, then we need to find
    # all elements that have their own class within this container, and make sure
    # that they are imported. Additionally, we need to find the elements that are
    # within a case, and ensure that these are built with the corresponding
    # choice specified.
    parentChildrenLeaf = {}
    for ch in i_children:
        if ch.keyword == "choice":
            for choice_ch in ch.i_children:
                # these are case statements
                for case_ch in choice_ch.i_children:
                    e = get_element(ctx, fdDict, case_ch, module, parent, \
                      path+"/"+ch.arg, parent_cfg=parent_cfg, \
                      choice=(ch.arg,choice_ch.arg))
                    if len([c.arg for c in choice_ch.i_children if c.keyword in ('leaf', 'leaf-list', 'choice')]) == len(choice_ch.i_children):
                        elements += e
                        #print 'element name', len(e), e[0]["name"], e
                    parentChildrenLeaf = {}
                    GetParentChildrenLeafs(ctx, case_ch.i_module, case_ch.parent, parentChildrenLeaf)

                    #elements += e
                    #print 'element name xx', len(e), e[0]["name"], e[0]
        else:
            e = get_element(ctx, fdDict, ch, module, parent, path+"/"+ch.arg,\
              parent_cfg=parent_cfg, choice=choice)
            # only add the element if this is an all leaf
            if len([c.arg for c in i_children if c.keyword in ('leaf', 'leaf-list', 'choice')]) == len(i_children):
                elements += e
                #print 'adding e', e[0]["name"]
                #print e[0]["name"]
                #if e[0]["name"].lower() == "members":
                #  print 'element name', len(e), e[0]["name"], len(i_children), len([c.arg for c in i_children if c.keyword in ('leaf', 'leaf-list')])
                #  for c in i_children:
                #    print c.arg, c.keyword, parent.keyword
            parentChildrenLeaf = {}
            GetParentChildrenLeafs(ctx, ch.i_module, ch.parent, parentChildrenLeaf)
            #print "additional children leafs", parentChildrenLeaf

    if len(elements) == 0:
        pass
    else:

        # 'container', 'module', 'list' and 'submodule' all have their own classes
        # generated.
        if parent.keyword in ["container", "module", "list", "submodule"]:

            # create struct skeleton
            # this will create the beginning of the struct definition
            structName = CreateStructSkeleton(module, fdDict["struct"], parent, path)
            if structName != '':
                #print 'creating unique class name', structName
                pass
                #addStructDescription(module, fdDict["struct"], parent, path)
            else:
                return None
        else:
            raise TypeError("unhandled keyword with children %s" % parent.keyword)

        # If the container is actually a list, then determine what the key value
        # is and store this such that we can give a hint.
        keyval = False
        if parent.keyword == "list":
            keyval = parent.search_one('key').arg if parent.search_one('key') \
                                          is not None else False
            if keyval and " " in keyval:
                keyval = keyval.split(" ")
            else:
                keyval = [keyval,]

        # only want to apply the parent leafs to Config structs
        #if structName.endswith('Config'):
        #  parentChildrenLeaf = {}

        # add the structure members
        addGOStructMembers(structName, elements, keyval, parentChildrenLeaf, fdDict["struct"])

        choices = {}
        choice_attrs = []
        classes = {}
        for i in elements:
            class_str = {}
            if "default" in i and not i["default"] is None:
                default_arg = repr(i["default"]) if i["quote_arg"] else "%s" \
                                            % i["default"]

                if 'u' in default_arg :
                    default_arg = default_arg.replace('u', '', 1).replace('\'', '')

            #if i["name"] == "Speed":
            #  print i
            class_str["name"] = "%s" % (i["name"][:1].upper() + i["name"][1:])
            class_str["default"] = 0
            class_str["base"] = ''
            if i["class"] == "leaf-list":
                # Map a leaf-list to the type specified in the class map. This is a
                # TypedList (see lib.yangtypes) with a particular set of types allowed.
                if isinstance(i["type"]["native_type"][1], list):
                    allowed_type = "["
                    for subtype in i["type"]["native_type"][1]:
                        allowed_type += "%s," % subtype
                    allowed_type += "]"
                else:
                    allowed_type = "%s" % (i["type"]["native_type"][1])

                class_str["base"] = "%s(allowed_type=%s)" % \
                  (i["type"]["native_type"][0],allowed_type)
                if "default" in i and not i["default"] is None:
                    class_str["default"] = default_arg
            #elif i["class"] == "list":
                # nothing to do
            elif i["class"] == "union" or i["class"] == "leaf-union":
                if "default" in i and not i["default"] is None:
                    class_str["default"] = default_arg
            #elif i["class"] == "leafref":

            #elif i["class"] == "leafref-list":

            else:
                if "default" in i and not i["default"] is None:
                    class_str["default"] = default_arg

            classes[i["name"]] = class_str

        # create NEW and Set methods
        # TODO: create get methods as well
        structName = createGONewStructMethod(ctx, module, classes, None, parent, path)
        #if structName != '' and not structName.endswith('State') and not structName.endswith('Counters'):
            # TODO need to add support for parentChildrenLeaf
        #    createGOStructMethods(elements, fdDict["func"], structName)

    return None


def addStructDescription(module, nfd, parent, path):
    # Auto-generate a docstring based on the description that is provided in
    # the YANG module. This aims to provide readability to someone perusing the
    # code that is generated.
    parent_descr = parent.search_one('description')
    if parent_descr is not None:
        parent_descr = "\n\n\tYANG Description: %s " % \
                       parent_descr.arg.decode('utf8').encode('ascii', 'ignore')
    else:
        parent_descr = ""

    # Add more helper text.
    nfd.write("""\t/*
      This class was auto-generated by the GOSTRUCT plugin for PYANG
      from YANG module %s
      based on the path %s.
      Each member element of the container is represented as a struct
      variable - with a specific YANG type.%s
      */\n""" % (module.arg, (path if not path == "" else "/%s" % parent.arg), \
                 parent_descr))


def CreateStructSkeleton(module, nfd, parent, path, write=True):
    global gOwnersInfo 
    global gYangObjInfo
    if not ENABLE_CAMEL_CASE:
        structName = '%s' % safe_name(parent.arg)
        if not path == "":
            structName = 'Yc_%s_%s_%s' % (safe_name(parent.arg),
                                          safe_name(module.arg),
                                          safe_name(path.replace("/", "_")))
        else:
            structName = 'Yc_%s' % (structName,)
    else:
        structName = '%s' % safe_name(safe_name(path.replace("/", "_")))

    if write and structName != '':
        if not gOwnersInfo or not gYangObjInfo:
            ownersData = srBase+ '/snaproute/src/models/objects/'+'yangObjInfo.json' 
            objsData = srBase+ '/snaproute/src/models/objects/'+'genObjectConfig.json' 
            with open(ownersData) as objInfoFile:    
                gOwnersInfo = json.load(objInfoFile)

            if not os.path.exists(objsData):
                print 'genObjectConfig does not exist'
                open(objsData, 'w').close() 
                gYangObjInfo = {}
            else:
                with open(objsData, 'a+') as objInfoFile:
                    try:
                        gYangObjInfo = json.load(objInfoFile)
                    except Exception as e:
                        print 'genObjectConfig exists but problem with json', e
                        gYangObjInfo = {}

        if parent.i_module.i_modulename in gOwnersInfo:

            owner =  gOwnersInfo[parent.i_module.i_modulename]
            srcFile = ''
            if nfd:
                nfd.write("type %s struct {\n" % structName)
                parts = nfd.stream.name.split('/')[-1].split('.')
                srcFile = '.'.join(parts[0:-1])

            multiplicity = '1'
            if parent.keyword == 'list':
                multiplicity = '*'
            access = 'w'
            for stmt in parent.i_children:
                if stmt.i_config == False:
                    access = 'r'

            gYangObjInfo[structName] =  {'access': access,
                                          'multiplicity':multiplicity,
                                          'owner': owner['owner'],
                                          'srcfile' : srcFile
                                        }
        else:
            structName = ''

    return structName

def createGONewStructMethod(ctx, module, classes, nfd, parent, path):

    structName = CreateStructSkeleton(module, nfd, parent, path, write=False)
    #if structName != '':
    #    nfd.write("""func (obj %s) UnmarshalObject(body []byte) (ConfigObj, error) {
    #    var err error
    #    if len(body) > 0 {
    #        if err = json.Unmarshal(body, &obj); err != nil  {
    #            fmt.Println("### %s called, unmarshal failed", obj, err)
    #        }
    #    }
    #    return obj, err
    #    }\n""" %(structName, structName))

    return structName

def setSelectionFromElemtype(elemtype,):
    isRange = False 
    elements_str = ""
    restriction = None
    if 'restriction_argument' in elemtype:
        restriction = elemtype['restriction_argument']
        elements_str += ", SELECTION: "
    if 'restriction_dict' in elemtype:
        if 'restriction_argument' in elemtype['restriction_dict']:
            restriction = elemtype['restriction_dict']['restriction_argument']
            elements_str += ", SELECTION: "
        else:
            if type(elemtype['restriction_dict']) == dict:
                for k, v in elemtype['restriction_dict'].iteritems():
                    if k == 'range':
                        isRange = True
                        range = v.split("..")
                        elements_str += ", MIN: \"%s\" ,  MAX: \"%s\"" %(int(range[0]), int(range[1]))
                    elif k == 'length':
                        if '..' in v:
                            range = v.split("..")
                            elements_str += ", MIN : \"%s\" ,MAX : \"%s\"" %(int(range[0]), int(range[1]))
                        else:
                            length = int(v)
                            elements_str += ", LEN : \"%s\"" %(length,)
                    else:
                        elements_str += ", SELECTION: \"%s\"" % v
    
    #if isRange:
    #    print elements_str
    if restriction:
        for k, v in restriction.iteritems():
            elements_str += "%s(%s)/" %(k, v['value'])
        elements_str = elements_str.rstrip('/')

    #if isRange:
    #    print elements_str
    return elements_str

def setDefaultFromElemtype(elem):
    elements_str = ""
    restriction = None
    if 'default' in elem and elem['default']:
        if 'elemtype' in elem:
            elemtype = elem['elemtype']
            if 'restriction_argument' in elemtype:
                restriction = elemtype['restriction_argument']
            if 'restriction_dict' in elemtype:
                if 'restriction_argument' in elemtype['restriction_dict']:
                    restriction = elemtype['restriction_dict']['restriction_argument']

        if restriction:
            for k, v in restriction.iteritems():
                if k == elem['default']:
                    if str(v['value']).isdigit():
                        elements_str += ", DEFAULT: %s" %(v['value'],)
                    else:
                        elements_str += ", DEFAULT: \"%s\"" %(v['value'],)
        else:
            if str(elem['default']).isdigit():
                elements_str += ", DEFAULT: %s" %(elem['default'],)
            else:
                elements_str += ", DEFAULT: \"%s\"" %(elem['default'],)

    return elements_str

def addGOStructMembers(structName, elements, keyval, parentChildrenLeaf, nfd):
    attrDescriptionDict = {}
    elements_str = "\n"

    keyname = keyval
    if isinstance(keyval, list):
        keyname = keyval[0]

    if keyname not in class_bool_map and \
       type(keyname) not in [type(1), bool]:
        keyname = keyname[:1].upper() + keyname[1:]

    childNameList = []
    for i in elements:
        childNameList.append(i["name"][:1].upper() + i["name"][1:])
        attrDescriptionDict[i['name']] =  i['description']

    for name, elemtype in parentChildrenLeaf.iteritems():
        attrDescriptionDict[name] = elemtype[2]

    # lets add the default interface functions from the ConfigObj
    elements_str += "\tConfigObj\n"

    elementList = []

    for name, elemtype in parentChildrenLeaf.iteritems():

        if safe_name(name) in elementList:
            continue
        if elemtype[1]:
            #elements_str += "\t// parent %s\n" % elemtype[0][0]
            if isinstance(elemtype[0][1]["native_type"], list):
                elements_str += "\t%s []%s %s" % (safe_name(name), elemtype[0][1]["native_type"][0], LIST_KEY_STR)
                elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))
            else:
                elements_str += "\t%s %s %s" % (safe_name(name), elemtype[0][1]["native_type"], LIST_KEY_STR)
                elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))
            elements_str += setSelectionFromElemtype(elemtype[0][1])
            elements_str += setDefaultFromElemtype(elemtype[0][1])
            elements_str += "`\n"
            elementList.append(safe_name(name))
        elif safe_name(name) not in childNameList:
            if elemtype[0] is None:
                print name, elemtype
            #elements_str += "\t// parent %s\n" % elemtype[0][0]
            if elemtype[0][0] != 'leaf-union':
                if isinstance(elemtype[0][1]["native_type"], list):
                    elements_str += "\t%s []%s" % (safe_name(name), elemtype[0][1]["native_type"][0])
                    elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))
                else:
                    elements_str += "\t%s %s" % (safe_name(name), elemtype[0][1]["native_type"])
                    elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))
                elements_str += setSelectionFromElemtype(elemtype[0][1])
                elements_str += setDefaultFromElemtype(elemtype[0][1])
                elements_str += "`\n"

                elementList.append(safe_name(name))
            else:
                for subtype in elemtype[0][1]:
                    # name just needs to be unique, choosing yang_type as postfix to the
                    # oritional varialble
                    subname = safe_name(subtype[1]["yang_type"])

                    elemName = name + "_" + subname
                    if elemName in elementList:
                        continue

                    membertype = subtype[1]["native_type"]
                    if isinstance(membertype, list):
                        membertype = "[]%s" % membertype[0]

                    if keyname == i["name"]:
                        elements_str += "\t%s %s  %s" % (elemName, membertype, LIST_KEY_STR)
                        elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))
                    else:
                        elements_str += "\t%s %s" % (elemName, membertype)
                        elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[name].replace('\n',' '))

                    elements_str += setSelectionFromElemtype(subtype[1])
                    elements_str += setDefaultFromElemtype(subtype[1])
                    elements_str += "`\n"
                    elementList.append(elemName)

    for i in elements:
        elemName = i["name"][:1].upper() + i["name"][1:]

        if elemName in elementList:
            continue

        if i["class"] == "leaf-list":
            #print '******************************************'
            #print "GO-STRUCT %s %s %s %s %s" % (elemName, i["class"], i["type"]["native_names"], i["type"]["native_type"], type(i["type"]["native_names"]))
            #print '******************************************'
            if isinstance(i["type"]["native_names"], list):
                if i["type"]["native_names"] is not None:
                    for subname, nativetype in zip(i["type"]["native_names"], i["type"]["native_type"]):
                        subsubname = safe_name(subname)

                        varname = nativetype
                        if isinstance(varname, list):
                            varname = varname[0]

                        elemName = elemName + '_' + subsubname

                        if elemName in elementList:
                            continue

                        if keyname == i["name"]:
                            elements_str += "\t%s %s  %s" % (elemName, varname, LIST_KEY_STR)
                            elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
                        else:
                            elements_str += "\t%s %s" % (elemName, varname)
                            elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))


                        if 'elemtype' in i:
                            elements_str += setSelectionFromElemtype(i['elemtype'])
                        elements_str += setDefaultFromElemtype(i)

                        elements_str += "`\n"
                        elementList.append(elemName)

                else:
                    varname = i["type"]["native_type"]
                    if isinstance(varname, list):
                        varname = varname[0]

                    if keyname == i["name"]:
                        elements_str += "\t%s []%s  %s" % (elemName, varname, LIST_KEY_STR)
                        elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
                    else:
                        elements_str += "\t%s []%s" % (elemName, varname)
                        elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))

                    if 'elemtype' in i:
                        elements_str += setSelectionFromElemtype(i['elemtype'])

                    elements_str += setDefaultFromElemtype(i)
                    elements_str += "`\n"
                    elementList.append(elemName)

            else:
                varname = i["type"]["native_type"]
                if isinstance(varname, list):
                    varname = varname[0]

                if keyname == i["name"]:
                    elements_str += "\t%s []%s  %s" % (elemName, varname, LIST_KEY_STR)
                    elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
                else:
                    elements_str += "\t%s []%s" % (elemName, varname)
                    elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))


                if 'elemtype' in i:
                    elements_str += setSelectionFromElemtype(i['elemtype'])
                elements_str += setDefaultFromElemtype(i)
                elements_str += "`\n"
                elementList.append(elemName)


        elif i["class"] == "list":
            #print '******************************************'
            #print "GO-STRUCT list %s %s %s %s" % (elemName, i["class"], i["type"], i["key"])
            #print '******************************************'
            listType = i["type"]

            if keyname == i["name"]:
                elements_str += "\t%s []%s  %s" % (elemName, listType, LIST_KEY_STR)
                elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
            else:
                elements_str += "\t%s []%s" % (elemName, listType)
                elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))


            if 'elemtype' in i:
                elements_str += setSelectionFromElemtype(i['elemtype'])
            elements_str += setDefaultFromElemtype(i)
            elements_str += "`\n"
            elementList.append(elemName)

        elif i["class"] == "union" or i["class"] == "leaf-union":
            #print '******************************************'
            #print "GO-STRUCT %s %s %s %s" % (elemName, i["class"], i["type"]["native_names"], i["type"]["native_type"])
            #print '******************************************'
            # lets append the union name to the element name
            for subtype in i["type"][1]:
                # name just needs to be unique, choosing yang_type as postfix to the
                # oritional varialble
                subname = safe_name(subtype[1]["yang_type"])

                elemName = elemName + "_" + subname

                if elemName in elementList:
                    continue

                membertype = subtype[1]["native_type"]
                if isinstance(membertype, list):
                    membertype = "[]%s" % membertype[0]

                if keyname == i["name"]:
                    elements_str += "\t%s %s  %s" % (elemName, membertype, LIST_KEY_STR)
                    elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
                else:
                    elements_str += "\t%s %s" % (elemName, membertype)
                    elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
                if 'elemtype' in i:
                    elements_str += setSelectionFromElemtype(i['elemtype'])
                elements_str += setDefaultFromElemtype(i)
                elements_str += "`\n"
                elementList.append(elemName)

        else:
            membertype = i["type"]
            if isinstance(membertype, list):
                membertype = "[]%s" % membertype[0]

            if keyname == i["name"]:
                elements_str += "\t%s %s  %s" % (elemName, membertype, LIST_KEY_STR)
                elements_str += " DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))
            else:
                elements_str += "\t%s %s" % (elemName, membertype)
                elements_str += " `DESCRIPTION: %s" %(attrDescriptionDict[elemName].replace('\n',' '))

            if 'elemtype' in i:
                elements_str += setSelectionFromElemtype(i['elemtype'])
            elements_str += setDefaultFromElemtype(i)
            elements_str += "`\n"
            elementList.append(elemName)

    elements_str += "}\n"
    nfd.write(elements_str + "\n")


def createGOStructMethods(elements, nfd, structName):

    def createBody(varName, i, precision, nfd):

        #print "CREATE BODY: ", varName, i, precision
        if "elemtype" in i and \
            "restriction_dict" in i["elemtype"] and \
            "range" in i["elemtype"]["restriction_dict"]:
            rangeStr = i["elemtype"]["restriction_dict"]["range"].strip('u').strip('\'')
            minMaxList = rangeStr.split('..')
            minVal, maxVal = minMaxList[0], minMaxList[1]

            if maxVal == 'max':
                maxVal = class_map[i["elemtype"]["native_type"]]["max"]

            nfd.write("\n\tif value < %s || value > %s {\n" % (minVal, maxVal))
            nfd.write("\t    return false\n")
            nfd.write("\t}\n")
        elif precision is not None:
            nfd.write("""\n
              \tvalue = float64(int(int(value) * (10 * precision)) / (10 * precision))\n""")
        nfd.write("""
          \td.%s = value
          \treturn true
          }\n""" % (varName,))

    for i in elements:
        skipBodyCreation = False
        precision = None
        varName = i["name"][:1].upper() + i["name"][1:]
        if i["class"] == "leaf-list":
            if isinstance(i["type"]["native_names"], list):
                for subname, nativetype in zip(i["type"]["native_names"], i["type"]["native_type"]):
                    subsubname = safe_name(subname)

                    argname = nativetype
                    if isinstance(argname, list):
                        argname = argname[0]

                    varName = varName + "_" + subsubname
                    nfd.write("func (d *%s) %s_Set(value %s) bool {" % (structName,
                              varName,
                              argname))
                    skipBodyCreation = True
                    createBody(varName, {}, None, nfd)

            else:
                argname = i["type"]["native_type"]
                if isinstance(argname, list):
                    argname = argname[0]
                nfd.write("func (d *%s) %s_Set(value []%s) bool {" % (structName, varName, argname))
        elif i["class"] == "restricted-decimal64":
            precision = i["elemtype"]['precision']
            nfd.write("func (d *%s) %s_Set(value %s, precision int) bool {" % (structName, varName, i["type"]))
        # elif i["class"] == "list":
        #  continue
        elif i["class"] == "union" or i["class"] == "leaf-union":

            for subtype in i["type"][1]:
                #print "UNION or UNION LEAF METHOD", subtype
                subargname = safe_name(subtype[1]["yang_type"])

                varName = varName + "_" + subargname
                argtype = subtype[1]["native_type"]
                if isinstance(argtype, list):
                    argtype = "[]%s" % argtype[0]

                nfd.write("func (d *%s) %s_Set(value %s) bool {" % (structName, varName, argtype))
                skipBodyCreation = True
                createBody(varName, {}, None, nfd)
        elif i["class"] == "list":
            argtype = "[]%s" % i["type"]
            nfd.write("func (d *%s) %s_Set(value %s) bool {" % (structName, varName, argtype))
        else:
            argtype = i["type"]
            if isinstance(argtype, list):
                argtype = "[]%s" % argtype[0]
            nfd.write("func (d *%s) %s_Set(value %s) bool {" % (structName, varName, argtype))

        #print '### Element type is %s' %(nfd.name)
        if not skipBodyCreation:
            createBody(varName, i, precision, nfd)

def build_elemtype(ctx, et, prefix=False):
    # Build a dictionary which defines the type for the element. This is used
    # both in the case that a typedef needs to be built, as well as on per-list
    # basis.
    cls = None
    pattern_stmt =  et.search_one('pattern') if not et.search_one('pattern') \
                                                is None else False
    range_stmt = et.search_one('range') if not et.search_one('range') \
                                                is None else False
    length_stmt = et.search_one('length') if not et.search_one('length') \
                                                is None else False


    # Determine whether there are any restrictions that are placed on this leaf,
    # and build a dictionary of the different restrictions to be placed on the
    # type.
    restrictions = {}
    if pattern_stmt:
        restrictions['pattern'] = pattern_stmt.arg

    if length_stmt:
        restrictions['length'] = length_stmt.arg

    if range_stmt:
        restrictions['range'] = range_stmt.arg

    # Build RestrictedClassTypes based on the compiled dictionary and the
    # underlying base type.
    if len(restrictions):
        if 'length' in restrictions or 'pattern' in restrictions:
            cls = "restricted-%s" % (et.arg)
            '''
            elemtype = {
                        "native_type": \
                          """RestrictedClassType(base_type=%s, restriction_dict=%s)"""
                            % (class_map[et.arg]["native_type"], repr(restrictions)),
                        "restriction_dict": restrictions,
                        "parent_type": et.arg,
                        "base_type": False,
                        }
            '''
            elemtype = {
                        "native_type":  """string""",
                        "restriction_dict": restrictions,
                        "parent_type": et.arg,
                        "base_type": False,
                        }
        elif 'range' in restrictions:
            cls = "restricted-%s" % et.arg
            '''
            elemtype = {
                        "native_type": \
                          """RestrictedClassType(base_type=%s, restriction_dict=%s)"""
                            % (class_map[et.arg]["native_type"], repr(restrictions)),
                        "restriction_dict": restrictions,
                        "parent_type": et.arg,
                        "base_type": False,
                       }
            '''
            elemtype = {
                        "native_type":  et.arg,
                        "restriction_dict": restrictions,
                        "parent_type": et.arg,
                        "base_type": False,
                       }

    # Handle all other types of leaves that are not restricted classes.
    if cls is None:
        cls = "leaf"
        # Enumerations are built as RestrictedClasses where the value that is
        # provided to the class is check against the keys of a dictionary.
        if et.arg == "enumeration":
            enumeration_dict = {}
            for enum in et.search('enum'):
                enumeration_dict[unicode(enum.arg)] = {}
                val = enum.i_value
                if val is not None:
                    enumeration_dict[unicode(enum.arg)]["value"] = int(val)
            elemtype = {"native_type": """int32""", \
                        "restriction_argument": enumeration_dict, \
                        "restriction_type": "dict_key", \
                        "parent_type": "string", \
                        "base_type": False,}
        # Map decimal64 to a RestrictedPrecisionDecimalType - this is there to
        # ensure that the fraction-digits argument can be implemented. Note that
        # fraction-digits is a mandatory argument.
        elif et.arg == "decimal64":
            fd_stmt = et.search_one('fraction-digits')
            if not fd_stmt is None:
                cls = "restricted-decimal64"
                elemtype = {"native_type": """float64""", \
                              "precision": fd_stmt.arg, "base_type": False, \
                              "parent_type": "decimal64",}
            else:
                elemtype = class_map[et.arg]
        # Handle unions - build a list of the supported types that are under the
        # union.
        elif et.arg == "union":
            elemtype = []
            for uniontype in et.search('type'):
                elemtype_s = copy.deepcopy(build_elemtype(ctx, uniontype))
                elemtype_s[1]["yang_type"] = uniontype.arg
                elemtype.append(elemtype_s)
            cls = "union"
        # Map leafrefs to a ReferenceType, handling the referenced path, and whether
        # require-instance is set. When xpathhelper is not specified, then no such
        # mapping is done - at this point, we solely map to a string.
        elif et.arg == "leafref":
            path_stmt = et.search_one('path')
            if path_stmt is None:
                raise ValueError("leafref specified with no path statement")
            require_instance = class_bool_map[et.search_one('require-instance').arg] \
                                if et.search_one('require-instance') \
                                  is not None else False
            if ctx.opts.use_xpathhelper:
                elemtype = {"native_type": "ReferenceType",
                            "referenced_path": path_stmt.arg,
                            "parent_type": "string",
                            "base_type": False,
                            "require_instance": require_instance}
                cls = "leafref"
            else:
                elemtype = {
                            "native_type": "string",
                            "parent_type": "string",
                            "base_type": False,
                           }
        # Handle identityrefs, but check whether there is a valid base where this
        # has been specified.
        elif et.arg == "identityref":
            base_stmt = et.search_one('base')
            if base_stmt is None:
                raise ValueError("identityref specified with no base statement")
            try:
                elemtype = class_map[base_stmt.arg]
            except KeyError:
                sys.stderr.write("FATAL: identityref with an unknown base\n")
                if DEBUG:
                    pp.pprint(class_map.keys())
                    pp.pprint(et.arg)
                    pp.pprint(base_stmt.arg)
                sys.exit(127)
        else:
            # For all other cases, then we should be able to look up directly in the
            # class_map for the defined type, since these are not 'derived' types
            # at this point. In the case that we are referencing a type that is a
            # typedef, then this has been added to the class_map.
            try:
                elemtype = class_map[et.arg]
            except KeyError:
                passed = False
                if prefix:
                    try:
                        tmp_name = "%s:%s" % (prefix, et.arg)
                        elemtype = class_map[tmp_name]
                        passed = True
                    except:
                        pass
                if passed == False:
                    sys.stderr.write("FATAL: unmapped type (%s)\n" % (et.arg))
                    if DEBUG:
                        pp.pprint(class_map.keys())
                        pp.pprint(et.arg)
                        pp.pprint(prefix)
                    sys.exit(127)
        if isinstance(elemtype, list):
            cls = "leaf-union"
        elif "class_override" in elemtype:
            # this is used to propagate the fact that in some cases the
            # native type needs to be dynamically built (e.g., leafref)
            cls = elemtype["class_override"]
    return (cls,elemtype)

def get_element(ctx, fdDict, element, module, parent, path,
                  parent_cfg=True, choice=False):
    # Handle mapping of an invidual element within the model. This function
    # produces a dictionary that can then be mapped into the relevant code that
    # dynamically generates a class.

    # NOTE: THIS IS A HACK AND SPECIFIC TO OPENCONFIG YANG files
    # BGP/VLAN/INTERFACE
    pathList = copy.copy(path.split('/'))
    modPathList = copy.copy(path.split('/'))
    #print 'orig:', pathList
    lengthPathList = len(pathList)
    if lengthPathList > 4 and pathList[-1] in ("config", "counters", "state"):
        for i in range(lengthPathList):
            # remove convention naming of list and name
            if i+1 < lengthPathList and pathList[i+1] == pathList[i][:-1] and pathList[i][-1] == 's':
                if i <= 1:
                    modPathList.remove(pathList[i+1])
                modPathList.remove(pathList[i])
        newpath = "/".join(modPathList)
    elif lengthPathList == 4 and pathList[-1] in ("config", "counters", "state"):
        if pathList[2] == pathList[1][:-1] and pathList[1][-1] == 's':
            modPathList.remove(pathList[1])
            newpath = "/".join(modPathList)
        else:
            newpath = path
    else:
        newpath = path


    this_object = []
    default = False
    has_children = False
    create_list = False

    elemdescr = element.search_one('description')
    if elemdescr is None:
        elemdescr = False
    else:
        elemdescr = elemdescr.arg

    # If the element has an i_children attribute then this is a container, list
    # leaf-list or choice.
    if hasattr(element, 'i_children'):
        if element.keyword in ["container", "list"]:
            has_children = True
        elif element.keyword in ["leaf-list"]:
            create_list = True

        # Fixup the path when within a choice, because this iteration belives that
        # we are under a new container, but this does not exist in the path.
        if element.keyword in ["choice"]:
            path_parts = newpath.split("/")
            npath = ""
            for i in range(0,len(path_parts)-1):
                npath += "%s/" % path_parts[i]
            npath.rstrip("/")
        else:
            npath=newpath

        # Create an element for a container.
        if element.i_children:
            #print "element has children", element.arg, len(element.i_children)
            chs = element.i_children
            get_children(ctx, fdDict, chs, module, element, npath, parent_cfg=parent_cfg,\
                         choice=choice)
            elemdict = {"name": safe_name(element.arg), "origtype": element.keyword,
                        "class": element.keyword,
                          "path": safe_name(npath), "config": True,
                          "description": elemdescr,
                          "yang_name": element.arg,
                          "choice": choice,
                       }
            # Handle the different cases of class name, this depends on whether we
            # were asked to split the bindings into a directory structure or not.

            elemdict["type"] = CreateStructSkeleton(module, None, element, newpath, write=False)

            # Deal with specific cases for list - such as the key and how it is
            # ordered.
            if element.keyword == "list":
                elemdict["key"] = safe_name(element.search_one("key").arg) \
                                    if element.search_one("key") is not None else False
                user_ordered = element.search_one('ordered-by')
                elemdict["user_ordered"] = True if user_ordered is not None \
                  and user_ordered.arg.upper() == "USER" else False
            this_object.append(elemdict)
            has_children = True

    # Deal with the cases that the attribute does not have children.
    if not has_children:
        if element.keyword in ["leaf-list"]:
            create_list = True
        cls,elemtype = copy.deepcopy(build_elemtype(ctx, element.search_one('type')))

        # Determine what the default for the leaf should be where there are
        # multiple available.
        # Algorithm:
        #   - build a tree that is rooted on this class.
        #   - perform a breadth-first search - the first node found
        #   - that has the "default" leaf set, then we take this
        #     as the value for the default

        # then starting at the selected default node, traverse
        # until we find a node that is declared to be a base_type
        elemdefault = element.search_one('default')
        default_type = False
        quote_arg = False
        if not elemdefault is None:
            elemdefault = elemdefault.arg
            default_type = elemtype
        if isinstance(elemtype, list):
            # this is a union, we should check whether any of the types
            # immediately has a default
            for i in elemtype:
                if "default" in i[1]:
                    elemdefault = i[1]["default"]
                    default_type = i[1]
                    #default_type = i[1]
                    #mapped_elemtype = i[1]
        elif "default" in elemtype:
            # if the actual type defines the default, then we need to maintain
            # this
            elemdefault = elemtype["default"]
            default_type = elemtype

        # we need to indicate that the default type for the class_map
        # is str
        tmp_class_map = copy.deepcopy(class_map)
        tmp_class_map["enumeration"] = {"parent_type": "string"}

        if not default_type:
            if isinstance(elemtype, list):
                # this type has multiple parents
                for i in elemtype:
                    if "parent_type" in i[1]:
                        if isinstance(i[1]["parent_type"], list):
                            to_visit = [j for j in i[1]["parent_type"]]
                        else:
                            to_visit = [i[1]["parent_type"],]
            elif "parent_type" in elemtype:
                if isinstance(elemtype["parent_type"], list):
                    to_visit = [i for i in elemtype["parent_type"]]
                else:
                    to_visit = [elemtype["parent_type"],]

                checked = list()
                while to_visit:
                    check = to_visit.pop(0)
                    if check not in checked:
                        checked.append(check)
                        if "parent_type" in tmp_class_map[check]:
                            if isinstance(tmp_class_map[check]["parent_type"], list):
                                to_visit.extend(tmp_class_map[check]["parent_type"])
                            else:
                                to_visit.append(tmp_class_map[check]["parent_type"])

                # checked now has the breadth-first search result
                if elemdefault is None:
                    for option in checked:
                        if "default" in tmp_class_map[option]:
                            elemdefault = tmp_class_map[option]["default"]
                            default_type = tmp_class_map[option]
                            break

        if elemdefault is not None:
            # we now need to check whether there's a need to
            # find out what the base type is for this type
            # we really expect a linear chain here.

            # if we have a tuple as the type here, this means that
            # the default was set at a level where there was not
            # a single option for the type. check the default
            # against each option, to get a to a single default_type
            if isinstance(default_type, list):
                # "first valid wins" as per rfc6020
                for i in default_type:
                    try:
                        disposible = i[1]["pytype"](elemdefault)
                        default_type = i[1]
                        break
                    except:
                        pass

            if not default_type["base_type"]:
                if "parent_type" in default_type:
                    if isinstance(default_type["parent_type"], list):
                        to_visit = [i for i in default_type["parent_type"]]
                    else:
                        to_visit = [default_type["parent_type"],]
                checked = list()
                while to_visit:
                    check = to_visit.pop(0) # remove from the top of stack - depth first
                    if not check in checked:
                        checked.append(check)
                        if "parent_type" in tmp_class_map[check]:
                            if isinstance(tmp_class_map[check]["parent_type"], list):
                                to_visit.expand(tmp_class_map[check]["parent_type"])
                            else:
                                to_visit.append(tmp_class_map[check]["parent_type"])
                default_type = tmp_class_map[checked.pop()]
                if not default_type["base_type"]:
                    raise TypeError("default type was not a base type")

        # Set the default type based on what was determined above about the
        # correct value to set.
        if default_type:
            quote_arg = default_type["quote_arg"] if "quote_arg" in \
                          default_type else False
            default_type = default_type["native_type"]

        elemconfig = class_bool_map[element.search_one('config').arg] if \
                                      element.search_one('config') else True

        elemname = safe_name(element.arg)

        # Deal with the cases that there is a requirement to create a list - these
        # are leaf lists. There is some special handling for leaf-lists to ensure
        # that the references are correctly created.
        subnames = None
        if create_list:
            if not cls == "leafref":
                cls = "leaf-list"
                #print "CREATE LIST", elemname, elemtype
                if isinstance(elemtype, list):
                    c = 0
                    allowed_types = []
                    subnames = []
                    for subtype in elemtype:
                        # nested union within a leaf-list type
                        if isinstance(subtype, tuple):
                            if subtype[0] == "leaf-union":
                                for subelemtype in subtype[1]["native_type"]:
                                    subnames.append(subelemtype["yang_type"])
                                    allowed_types.append(subelemtype)
                            else:
                                if isinstance(subtype[1]["native_type"], list):
                                    subnames.append(subtype[1]["yang_type"])
                                    allowed_types.extend(subtype[1]["native_type"])
                                else:
                                    subnames.append(subtype[1]["yang_type"])
                                    allowed_types.append(subtype[1]["native_type"])
                        else:
                            subnames.append(subtype["yang_type"])
                            allowed_types.append(subtype["native_type"])
                else:
                    allowed_types = elemtype["native_type"]

            else:
                cls = "leafref-list"
                allowed_types = {
                                  "native_type": elemtype["native_type"],
                                  "referenced_path": elemtype["referenced_path"],
                                  "require_instance": elemtype["require_instance"],
                                }

            elemntype = {"class": cls, "native_type": allowed_types, "native_names": subnames}

        else:
            if cls == "union" or cls == "leaf-union":
                elemtype = {"class": cls, "native_type": ("UnionType", elemtype)}
            elemntype = elemtype["native_type"]

        # Build the dictionary for the element with the relevant meta-data specified
        # within it.
        elemdict = {"name": elemname, "type": elemntype,
                            "origtype": element.search_one('type').arg, "path": \
                            safe_name(newpath),
                            "class": cls, "default": elemdefault, \
                            "config": elemconfig, "defaulttype": default_type, \
                            "quote_arg": quote_arg, \
                            "description": elemdescr, "yang_name": element.arg,
                            "choice": choice,
                            "elemtype": elemtype,
                   }
        if cls == "leafref":
            elemdict["referenced_path"] = elemtype["referenced_path"]
            elemdict["require_instance"] = elemtype["require_instance"]

        # In cases where there there are a set of interesting extensions specified
        # then build a dictionary of these extension values to provide with the
        # specific leaf for this element.
        if element.substmts is not None and ctx.opts.pybind_interested_exts is not None:
            extensions = {}
            for ext in element.substmts:
                if ext.keyword[0] in ctx.opts.pybind_interested_exts:
                    if not ext.keyword[0] in extensions:
                        extensions[ext.keyword[0]] = {}
                    extensions[ext.keyword[0]][ext.keyword[1]] = ext.arg
            if len(extensions):
                elemdict["extensions"] = extensions

        this_object.append(elemdict)

    return this_object
