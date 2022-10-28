from capa.features.extractors.viv import extractor as viv_extractor
from capa.features.extractors.base_extractor import FunctionHandle, FeatureExtractor
from capa.rules import Rule, Scope, RuleSet
from typing import Any, Dict, List, Tuple
from capa.engine import FeatureSet, MatchResults
import capa.engine

import collections
import itertools
import viv_utils
import os

# "encrypt data *"
# "encrypt or decrypt *"


encryption_rules = [
    "encrypt data using Salsa20 or ChaCha",
    "reference Salsa20 or ChaCha setup",
    "encrypt data using AES via x86 extensions",
    "encrypt or decrypt data via BCrypt",
    "encrypt data using FAKEM cipher wrapper", #BB
    "encrypt data via SSPI wrapper", #BB
    "reference AES constants",
    "encrypt data using DES via WinAPI",
    "manually build AES constants",
    "encrypt data using DES wrapper", #BB
    "encrypt or decrypt via WinCrypt",
    "reference public RSA key",
    "encrypt data using RC4 KSA",
    "encrypt data using RC4 PRGA",
    "encrypt data using RC4 via WinAPI",
    "encrypt data using RC4 with custom key via WinAPI",
    "encrypt data using Curve25519 wrapper", #BB
    "encrypt data using HC-128 via WolfSSL wrapper", #BB
    "encrypt data using HC-128 wrapper", #BB
    "generate random numbers via WinAPI",
    "create new key via CryptAcquireContext",
    
    "encrypt data using RC6",
    "encrypt data using Camellia wrapper", #BB
    "encrypt data using RC4 via WinAPI",
    "encrypt data using memfrob from glibc",
    "encrypt data using blowfish wrapper", #BB
    "encrypt data using skipjack wrapper", #BB
    "encrypt data using Sosemanuk wrapper", #BB
    "encrypt data using DES via WinAPI",
    "encrypt data using vest wrapper", #BB
    "encrypt data using DPAPI",
    "encrypt data using twofish wrapper", #BB
    "generate random numbers using a Mersenne Twister",
    "generate random numbers using the Delphi LCG wrapper", #BB

    "allocate execute memory", #BB # for findout shellcode
    "encrypt data using R5A",
    "lib function - ucrtbased!__acrt_stdio_allocate_stream",
    "lib function - ucrtbased!common_fsopen",
]

def main(vw, sample_path, rules_path):
    ### extract feature

    extractor = viv_extractor.VivisectFeatureExtractor(vw, sample_path)

    ### setup rules
    rules = get_rules(rules_path)
    rules = RuleSet(rules)

    ### match
    result = []
    capabilities, counts = find_capabilities(rules, extractor, disable_progress=True)
    for rule_name, matches in capabilities.items():
        # rule = rules[rule_name]
        if rule_name in encryption_rules:
            result.append({
                # "source": rule.definition,
                'rule_name': rule_name,
                "matches": {
                    addr: convert_match_to_result_document(rules, capabilities, match) for (addr, match) in matches
                },
            })

    return result

def get_rules(rule_path: str, disable_progress=False) -> List[Rule]:
    if not os.path.exists(rule_path):
        raise IOError("rule path %s does not exist or cannot be accessed" % rule_path)

    rule_paths = []
    if os.path.isfile(rule_path):
        rule_paths.append(rule_path)
    elif os.path.isdir(rule_path):
        # print("reading rules from directory %s", rule_path)
        for root, dirs, files in os.walk(rule_path):
            if ".github" in root:
                # the .github directory contains CI config in capa-rules
                # this includes some .yml files
                # these are not rules
                continue

            for file in files:
                if not file.endswith(".yml"):
                    if not (file.startswith(".git") or file.endswith((".git", ".md", ".txt"))):
                        # expect to see .git* files, readme.md, format.md, and maybe a .git directory
                        # other things maybe are rules, but are mis-named.
                        print("skipping non-.yml file: %s", file)
                    continue

                rule_path = os.path.join(root, file)
                rule_paths.append(rule_path)

    rules = []  # type: List[Rule]

    

    for rule_path in list(rule_paths):
        try:
            rule = capa.rules.Rule.from_yaml_file(rule_path)
        except capa.rules.InvalidRule:
            raise
        else:
            rule.meta["capa/path"] = rule_path
            if is_nursery_rule_path(rule_path):
                rule.meta["capa/nursery"] = True

            rules.append(rule)
            #print("loaded rule: '%s' with scope: %s" % (rule.name, rule.scope))

    return rules

def is_nursery_rule_path(path: str) -> bool:
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    The nursery is currently a subdirectory of the rules directory with that name.

    When nursery rules are loaded, their metadata section should be updated with:
      `nursery=True`.
    """
    return "nursery" in path

def convert_capabilities_to_result_document(meta, rules: RuleSet, capabilities: MatchResults):
    doc = {
        "meta": meta,
        "rules": {},
    }

    for rule_name, matches in capabilities.items():
        rule = rules[rule_name]

        if rule.meta.get("capa/subscope-rule"):
            continue


        doc["rules"][rule_name] = {
            "source": rule.definition,
            "matches": {
                addr: convert_match_to_result_document(rules, capabilities, match) for (addr, match) in matches
            },
        }

    return doc

def convert_match_to_result_document(rules, capabilities, result):
    """
    convert the given Result instance into a common, Python-native data structure.
    this will become part of the "result document" format that can be emitted to JSON.
    """
    doc = {
        "success": bool(result.success),
        "node": convert_node_to_result_document(result.statement),
        "children": [convert_match_to_result_document(rules, capabilities, child) for child in result.children],
    }

    # logic expression, like `and`, don't have locations - their children do.
    # so only add `locations` to feature nodes.
    if isinstance(result.statement, capa.features.common.Feature):
        if bool(result.success):
            doc["locations"] = result.locations
    elif isinstance(result.statement, capa.engine.Range):
        if bool(result.success):
            doc["locations"] = result.locations

    # if we have a `match` statement, then we're referencing another rule or namespace.
    # this could an external rule (written by a human), or
    #  rule generated to support a subscope (basic block, etc.)
    # we still want to include the matching logic in this tree.
    #
    # so, we need to lookup the other rule results
    # and then filter those down to the address used here.
    # finally, splice that logic into this tree.
    if (
        doc["node"]["type"] == "feature"
        and doc["node"]["feature"]["type"] == "match"
        # only add subtree on success,
        # because there won't be results for the other rule on failure.
        and doc["success"]
    ):

        name = doc["node"]["feature"]["match"]

        if name in rules:
            # this is a rule that we're matching
            #
            # pull matches from the referenced rule into our tree here.
            rule_name = doc["node"]["feature"]["match"]
            rule = rules[rule_name]
            rule_matches = {address: result for (address, result) in capabilities[rule_name]}

            if rule.meta.get("capa/subscope-rule"):
                # for a subscope rule, fixup the node to be a scope node, rather than a match feature node.
                #
                # e.g. `contain loop/30c4c78e29bf4d54894fc74f664c62e8` -> `basic block`
                scope = rule.meta["scope"]
                doc["node"] = {
                    "type": "statement",
                    "statement": {
                        "type": "subscope",
                        "subscope": scope,
                    },
                }

            for location in doc["locations"]:
                # print(location)
                # print(rule_matches)
                # print(rules)
                doc["children"].append(convert_match_to_result_document(rules, capabilities, rule_matches[location]))
        else:
            # this is a namespace that we're matching
            #
            # check for all rules in the namespace,
            # seeing if they matched.
            # if so, pull their matches into our match tree here.
            ns_name = doc["node"]["feature"]["match"]
            ns_rules = rules.rules_by_namespace[ns_name]

            for rule in ns_rules:
                if rule.name in capabilities:
                    # the rule matched, so splice results into our tree here.
                    #
                    # note, there's a shortcoming in our result document schema here:
                    # we lose the name of the rule that matched in a namespace.
                    # for example, if we have a statement: `match: runtime/dotnet`
                    # and we get matches, we can say the following:
                    #
                    #     match: runtime/dotnet @ 0x0
                    #       or:
                    #         import: mscoree._CorExeMain @ 0x402000
                    #
                    # however, we lose the fact that it was rule
                    #   "compiled to the .NET platform"
                    # that contained this logic and did the match.
                    #
                    # we could introduce an intermediate node here.
                    # this would be a breaking change and require updates to the renderers.
                    # in the meantime, the above might be sufficient.
                    rule_matches = {address: result for (address, result) in capabilities[rule.name]}
                    for location in doc["locations"]:
                        # doc[locations] contains all matches for the given namespace.
                        # for example, the feature might be `match: anti-analysis/packer`
                        # which matches against "generic unpacker" and "UPX".
                        # in this case, doc[locations] contains locations for *both* of thse.
                        #
                        # rule_matches contains the matches for the specific rule.
                        # this is a subset of doc[locations].
                        #
                        # so, grab only the locations for current rule.
                        if location in rule_matches:
                            doc["children"].append(
                                convert_match_to_result_document(rules, capabilities, rule_matches[location])
                            )

    return doc

def convert_statement_to_result_document(statement):
    """
    "statement": {
        "type": "or"
    },

    "statement": {
        "max": 9223372036854775808,
        "min": 2,
        "type": "range"
    },
    """
    statement_type = statement.name.lower()
    result = {"type": statement_type}
    if statement.description:
        result["description"] = statement.description

    if statement_type == "some" and statement.count == 0:
        result["type"] = "optional"
    elif statement_type == "some":
        result["count"] = statement.count
    elif statement_type == "range":
        result["min"] = statement.min
        result["max"] = statement.max
        result["child"] = convert_feature_to_result_document(statement.child)
    elif statement_type == "subscope":
        result["subscope"] = statement.scope

    return result


def convert_feature_to_result_document(feature):
    """
    "feature": {
        "number": 6,
        "type": "number"
    },

    "feature": {
        "api": "ws2_32.WSASocket",
        "type": "api"
    },

    "feature": {
        "match": "create TCP socket",
        "type": "match"
    },

    "feature": {
        "characteristic": [
            "loop",
            true
        ],
        "type": "characteristic"
    },
    """
    result = {"type": feature.name, feature.name: feature.get_value_str()}
    if feature.description:
        result["description"] = feature.description
    if feature.name in ("regex", "substring"):
        result["matches"] = feature.matches
    return result


def convert_node_to_result_document(node):
    """
    "node": {
        "type": "statement",
        "statement": { ... }
    },

    "node": {
        "type": "feature",
        "feature": { ... }
    },
    """

    if isinstance(node, capa.engine.Statement):
        return {
            "type": "statement",
            "statement": convert_statement_to_result_document(node),
        }
    elif isinstance(node, capa.features.common.Feature):
        return {
            "type": "feature",
            "feature": convert_feature_to_result_document(node),
        }
    else:
        raise RuntimeError("unexpected match node type")


def find_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, disable_progress=None) -> Tuple[MatchResults, Any]:
    all_function_matches = collections.defaultdict(list)  # type: MatchResults
    all_bb_matches = collections.defaultdict(list)  # type: MatchResults

    meta = {
        "feature_counts": {
            "file": 0,
            "functions": {},
        },
        "library_functions": {},
    }  # type: Dict[str, Any]

    # pbar = tqdm.tqdm
    # if disable_progress:
    #     # do not use tqdm to avoid unnecessary side effects when caller intends
    #     # to disable progress completely
    #     pbar = lambda s, *args, **kwargs: s

    functions = list(extractor.get_functions())
    n_funcs = len(functions)

    # pb = pbar(functions, desc="matching", unit=" functions", postfix="skipped 0 library functions")
    for f in functions:
        function_address = int(f.address)

        if extractor.is_library_function(function_address):
            function_name = extractor.get_function_name(function_address)
            print("skipping library function 0x%x (%s)" %  (function_address, function_name))
            meta["library_functions"][function_address] = function_name
            n_libs = len(meta["library_functions"])
            percentage = 100 * (n_libs / n_funcs)
            # if isinstance(pb, tqdm.tqdm):
            #     pb.set_postfix_str("skipped %d library functions (%d%%)" % (n_libs, percentage))
            continue

        function_matches, bb_matches, feature_count = find_function_capabilities(ruleset, extractor, f)
        # print("bb_matches ", bb_matches)
        meta["feature_counts"]["functions"][function_address] = feature_count
        #print("analyzed function 0x%x and extracted %d features" % ( function_address, feature_count))

        for rule_name, res in function_matches.items():
            all_function_matches[rule_name].extend(res)
        for rule_name, res in bb_matches.items():
            all_bb_matches[rule_name].extend(res)

    # collection of features that captures the rule matches within function and BB scopes.
    # mapping from feature (matched rule) to set of addresses at which it matched.
    function_and_lower_features: FeatureSet = collections.defaultdict(set)
    for rule_name, results in itertools.chain(all_function_matches.items(), all_bb_matches.items()):
        locations = set(map(lambda p: p[0], results))
        rule = ruleset[rule_name]
        capa.engine.index_rule_matches(function_and_lower_features, rule, locations)

    all_file_matches, feature_count = find_file_capabilities(ruleset, extractor, function_and_lower_features)
    meta["feature_counts"]["file"] = feature_count

    matches = {
        rule_name: results
        for rule_name, results in itertools.chain(
            # each rule exists in exactly one scope,
            # so there won't be any overlap among these following MatchResults,
            # and we can merge the dictionaries naively.
            all_bb_matches.items(),
            all_function_matches.items(),
            all_file_matches.items(),
        )
    }
    # print(all_bb_matches.items())

    return matches, meta

def find_function_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, f: FunctionHandle):
    # contains features from:
    #  - insns
    #  - function
    function_features = collections.defaultdict(set)  # type: FeatureSet
    bb_matches = collections.defaultdict(list)  # type: MatchResults

    for feature, va in itertools.chain(extractor.extract_function_features(f), extractor.extract_global_features()):
        function_features[feature].add(va)

    for bb in extractor.get_basic_blocks(f):
        # contains features from:
        #  - insns
        #  - basic blocks
        bb_features = collections.defaultdict(set)

        for feature, va in itertools.chain(
            extractor.extract_basic_block_features(f, bb), extractor.extract_global_features()
        ):
            bb_features[feature].add(va)
            function_features[feature].add(va)

        for insn in extractor.get_instructions(f, bb):
            for feature, va in itertools.chain(
                extractor.extract_insn_features(f, bb, insn), extractor.extract_global_features()
            ):
                bb_features[feature].add(va)
                function_features[feature].add(va)

        _, matches = ruleset.match(Scope.BASIC_BLOCK, bb_features, int(bb.address))
        # print(f, matches)

        for rule_name, res in matches.items():
            
            rule = ruleset[rule_name]
            for va, _ in res:
                capa.engine.index_rule_matches(function_features, rule, [va])
            
            # [TODO]
            # res = [(int(f),_) for va, _ in res]    
            bb_matches[rule_name].extend(res)

    _, function_matches = ruleset.match(Scope.FUNCTION, function_features, int(f.address))
    # print("function_matches: ", function_matches)
    # print("bb_matches: ", bb_matches)

    return function_matches, bb_matches, len(function_features)


def find_file_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, function_features: FeatureSet):
    file_features = collections.defaultdict(set)  # type: FeatureSet

    for feature, va in itertools.chain(extractor.extract_file_features(), extractor.extract_global_features()):
        # not all file features may have virtual addresses.
        # if not, then at least ensure the feature shows up in the index.
        # the set of addresses will still be empty.
        if va:
            file_features[feature].add(va)
        else:
            if feature not in file_features:
                file_features[feature] = set()

    # print("analyzed file and extracted %d features", len(file_features))

    file_features.update(function_features)

    _, matches = ruleset.match(Scope.FILE, file_features, 0x0)
    return matches, len(file_features)

def print_result(result):
    fva_list = {
        "encrypts": {},
        "file_ops": {}
    }
    for matched_rule in result:
        if matched_rule['rule_name'] == "allocate execute memory":
            print("========== probabaly shellcode ==========")
            exit(0) # early stop

        for func_addr, data in matched_rule['matches'].items():
            print(f"[+] fva: {hex(func_addr)}, {matched_rule['rule_name']} ")
            if not "lib function" in matched_rule['rule_name']:
                if func_addr in fva_list["encrypts"].keys():
                    fva_list["encrypts"][func_addr].append(matched_rule['rule_name'])
                else:
                    fva_list["encrypts"][func_addr] = [matched_rule['rule_name']]
            else: 
                if func_addr in fva_list["file_ops"].keys():
                    fva_list["file_ops"][func_addr].append(matched_rule['rule_name'])
                else:
                    fva_list["file_ops"][func_addr] = [matched_rule['rule_name']]
            # print_matched(data)
    return fva_list

def print_matched(data, layer=1):
    if data['success']:
        if len(data['children']) == 0:
            for loc in data['locations']:
                print("  "*layer + "insn_addr:", hex(loc))
        else:
            for c in data['children']:
                print_matched(c, layer+1)

def capaScan(vw, pathToSample, pathToRules):

    # a better idea is to have a forked vw object from the TCSA Engine.
    vw = viv_utils.getWorkspace(pathToSample, analyze=True, should_save=False)

    return main(vw, pathToSample, pathToRules)
