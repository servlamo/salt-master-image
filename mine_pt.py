"""
A PT runner to access data from the salt mine
"""


import os
import salt.config
import salt.syspaths
import salt.cache
import salt.utils.verify
import salt.utils.minions
import salt.payload
import logging


log = logging.getLogger(__name__)


def _mine_pt_get(load, skip_verify=False):
    """
    Gathers the data from the specified minions' mine
    """
    cache_driver = __opts__.get("cache", salt.config.DEFAULT_MASTER_OPTS["cache"])
    cache_dir = __opts__.get("cachedir", salt.syspaths.CACHE_DIR)
    cache = salt.cache.factory(__opts__)
    if not skip_verify:
        if any(key not in load for key in ("id", "tgt", "fun")):
            return {}

    if isinstance(load["fun"], str):
        functions = list(set(load["fun"].split(",")))
        _ret_dict = len(functions) > 1
    elif isinstance(load["fun"], list):
        functions = load["fun"]
        _ret_dict = True
    else:
        return {}

    functions_allowed = []

    if "mine_get" in __opts__:
        # If master side acl defined.
        if not isinstance(__opts__["mine_get"], dict):
            return {}
        perms = set()
        for match in __opts__["mine_get"]:
            if re.match(match, load["id"]):
                if isinstance(__opts__["mine_get"][match], list):
                    perms.update(__opts__["mine_get"][match])
        for fun in functions:
            if any(re.match(perm, fun) for perm in perms):
                functions_allowed.append(fun)
        if not functions_allowed:
            return {}
    else:
        functions_allowed = functions

    ret = {}
    if not salt.utils.verify.valid_id(__opts__, load["id"]):
        return {}

    expr_form = load.get("expr_form")
    # keep both expr_form and tgt_type to ensure
    # comptability between old versions of salt
    if expr_form is not None and "tgt_type" not in load:
        match_type = expr_form
    else:
        match_type = load.get("tgt_type", "glob")
    if match_type.lower() == "pillar":
        match_type = "pillar_exact"
    if match_type.lower() == "compound":
        match_type = "compound_pillar_exact"
    checker = salt.utils.minions.CkMinions(__opts__)
    _res = checker.check_minions(load["tgt"], match_type, greedy=False)
    minions = _res["minions"]
    minion_side_acl = {}  # Cache minion-side ACL
    for minion in minions:
        if not __opts__.get("memcache_expire_seconds", 0):
            inkey = False
            bank = "minions/{}".format(minion)
            key = "mine"
            key_file = os.path.join(cache_dir, os.path.normpath(bank), "{}.p".format(key))
            if not os.path.isfile(key_file):
                # The bank includes the full filename, and the key is inside the file
                key_file = os.path.join(cache_dir, os.path.normpath(bank) + ".p")
                inkey = True
            if not os.path.isfile(key_file):
                log.debug('Cache file "%s" does not exist', key_file)
                continue
            try:
                with salt.utils.files.fopen(key_file, "rb") as fh_:
                    if inkey:
                        mine_data = salt.payload.load(fh_)[key]
                    else:
                        mine_data = salt.payload.load(fh_)
            except OSError as exc:
                raise SaltCacheError(
                    'There was an error reading the cache file "{}": {}'.format(key_file, exc)
                )
        if not isinstance(mine_data, dict):
            continue
        for function in functions_allowed:
            if function not in mine_data:
                continue
            mine_entry = mine_data[function]
            mine_result = mine_data[function]
            if (
                isinstance(mine_entry, dict)
                and salt.utils.mine.MINE_ITEM_ACL_ID in mine_entry
            ):
                mine_result = mine_entry[salt.utils.mine.MINE_ITEM_ACL_DATA]
                # Check and fill minion-side ACL cache
                if function not in minion_side_acl.get(minion, {}):
                    if "allow_tgt" in mine_entry:
                        # Only determine allowed targets if any have been specified.
                        # This prevents having to add a list of all minions as allowed targets.
                        get_minion = checker.check_minions(
                            mine_entry["allow_tgt"],
                            mine_entry.get("allow_tgt_type", "glob"),
                        )["minions"]
                        # the minion in allow_tgt does not exist
                        if not get_minion:
                            continue
                        salt.utils.dictupdate.set_dict_key_value(
                            minion_side_acl,
                            "{}:{}".format(minion, function),
                            get_minion,
                        )
            minion_acl_entry = minion_side_acl.get(minion, {}).get(function, [])
            ret_acl = minion_acl_entry and load["id"] not in minion_acl_entry
#           if ret_acl:
#               log.debug(
#                   "Salt mine request from %s for function %s on minion %s denied.",
#                   load["id"],
#                   function,
#                   minion,
#               )
#               continue
            if _ret_dict:
                ret.setdefault(function, {})[minion] = mine_result
            else:
                # There is only one function in functions_allowed.
                ret[minion] = mine_result

    return ret


def get(tgt, fun, tgt_type="glob"):
    """
    Gathers the data from the specified minions' mine, pass in the target,
    function to look up and the target type

    CLI Example:

    .. code-block:: bash

        salt-run mine_pt.get '*' network.interfaces
    """
    load = {
        "id": __opts__["id"],
        "fun": fun,
        "tgt": tgt,
        "tgt_type": tgt_type,
    }
    ret = _mine_pt_get(load)
    return ret

