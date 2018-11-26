#!/usr/bin/python

"""

    @author: Ivica Arsov

"""

import datetime
import subprocess
import re
import time
import json
from distutils.util import strtobool
try:
    import pexpect
    pexpect_found = True
except ImportError:
    pexpect_found = False
import os

from ansible.module_utils.basic import AnsibleModule
#global module

g_function = "CHECK_OPATCH_MIN_VERSION"

g_file_oratab = "/etc/oratab"
#g_sw_opatch_check_conflict_pattern = "((.|\n)*)(Prereq \"checkConflictAgainstOHWithDetail\" passed)((.|\n)*)"
#g_sw_opatch_spacecheck_pattern = "((.|\n)*)(Prereq \"checkSystemSpace\" passed)((.|\n)*)"
#g_sw_opatch_min_version = "((.|\n)*)(Prereq \"checkMinimumOPatchVersion\" passed)((.|\n)*)"
#g_sw_opatch_check_pattern = "((.|\n)*)(OPatch succeeded|OPatch completed with warnings)((.|\n)*)"
#g_sw_opatch_no_need = "((.|\n)*)(No need to apply this patch)((.|\n)*)"
#g_sw_opatchauto_check_pattern = "((.|\n)*)(OPatchAuto successful)((.|\n)*)"
g_sw_opatch_check_conflict_pattern = "Prereq \"checkConflictAgainstOHWithDetail\" passed"
g_sw_opatch_spacecheck_pattern = "Prereq \"checkSystemSpace\" passed"
g_sw_opatch_min_version = "Prereq \"checkMinimumOPatchVersion\" passed"
g_sw_opatch_check_pattern1 = "OPatch succeeded"
g_sw_opatch_check_pattern2 = "OPatch completed with warnings"
g_sw_opatch_no_need = "No need to apply this patch"
g_sw_opatchauto_check_pattern12 = "OPatchAuto successful"
g_sw_opatchauto_check_pattern11 = "opatch auto succeeded"

g_root_password = None
g_changed = False
g_output = {}
g_instance_list = {}
g_listener_list = {}

#g_expected_list = {}
g_expected_list = { 'Do you want to proceed\? \[y\|n\]'.decode(): 'y\r'.decode(),
                'Email address/User Name:'.decode(): '\r'.decode(),
                'Do you wish to remain uninformed of security issues \(\[Y\]es, \[N\]o\) \[N\]'.decode(): 'y\r'.decode(),
                'Is the local system ready for patching\? \[y\|n\]'.decode(): 'y\r'.decode() }

#g_logger_file = "/tmp/orapatch_run_" + time.strftime("%Y-%m-%d_%I-%M-%S%p")+".log"
g_logger_file = ""
g_ocmrf_file = "/tmp/orapatch_ocm_" + time.strftime("%Y-%m-%d_%I-%M-%S%p")+".rsp"

def to_bool(p_value):
    """
       Converts 'something' to boolean. Raises exception for invalid formats
           Possible True  values: 1, True, "1", "TRue", "yes", "y", "t"
           Possible False values: 0, False, None, [], {}, "", "0", "faLse", "no", "n", "f", 0.0, ...
    """
    if str(p_value).lower() in ("yes", "y", "true",  "t", "1"): return True
    if str(p_value).lower() in ("no",  "n", "false", "f", "0", "0.0", "", "none", "[]", "{}"): return False

    raise Exception('Invalid value for boolean conversion: ' + str(value))

def fail_module(p_message, p_code = 245):
    logger("Module fail: " + str (p_message))
    module.fail_json(rc = p_code, msg = p_message)

def gettime():

    return time.strftime("%Y-%m-%d_%H-%M-%S")

def logger(p_message, p_notime = False):

    if not p_notime:

        v_message = time.strftime("%c")+"\n" + p_message+"\n"

    else:

        v_message = p_message+"\n"

    f = open(g_logger_file,'a')
    f.write(v_message)
    f.close

def start_logger_session():

    logger("--------------------------------", True)
    logger("orapatch session start")
    logger("--------------------------------", True)

def end_logger_session():

    logger("--------------------------------", True)
    logger("orapatch session end")
    logger("--------------------------------", True)


class DatabaseFactory(object):

    def __init__(self, p_sid, p_version, p_db_name, p_is_asm = False, p_is_rac = False
                     , p_is_standby = False, p_instance_list = None, p_is_active = False
                     , p_initial_state = None, p_oracle_home = None):

        self.sid            = p_sid
        self.version        = p_version
        self.name           = p_db_name
        self.is_asm         = p_is_asm
        self.is_rac         = p_is_rac
        self.is_standby     = p_is_standby
        self.instance_list  = p_instance_list
        self.is_active      = p_is_active
        self.initial_state  = p_initial_state
        self.version_short  = int (p_version.split('.')[0])
        self.oracle_home    = p_oracle_home

        #initial state: DOWN|MOUNTED|OPEN

class ListenerFactory(object):

    def __init__(self, p_listener_name, p_oracle_home):

        self.listener_name = p_listener_name
        self.oracle_home = p_oracle_home

class PatchFactory(object):

    def __init__(self,  p_patch_id,
                        p_patch_proactive_bp_id,
                        p_patch_gi_id,
                        p_patch_db_id,
                        p_patch_ocw_id,
                        p_patch_ojvm_id,
                        p_patch_acfs_id,
                        p_patch_dbwlm_id,
                        p_patch_dir,
                        p_file,
                        p_only_oh,
                        p_desc):

        self.patch_id               = p_patch_id
        self.patch_proactive_bp_id  = p_patch_proactive_bp_id
        self.patch_gi_id            = p_patch_gi_id
        self.patch_db_id            = p_patch_db_id
        self.patch_ocw_id           = p_patch_ocw_id
        self.patch_ojvm_id          = p_patch_ojvm_id
        self.patch_dir              = str (p_patch_dir)
        self.file                   = p_file
        self.desc                   = p_desc
        self.only_oh                = p_only_oh
        self.patch_acfs_id          = p_patch_acfs_id
        self.patch_dbwlm_id         = p_patch_dbwlm_id

        if p_patch_proactive_bp_id:
            self.is_dbbp = True
        else:
            self.is_dbbp = False

        if p_patch_ojvm_id and (p_patch_proactive_bp_id or p_patch_db_id or patch_gi_id):
            self.is_combo = True
        else:
            self.is_combo = False

        if p_patch_gi_id:
            self.is_grid = True
        else:
            self.is_grid = False

class PatchProcess(object):

    def __init__(self, p_oracle_home, p_only_prereq,
                       p_patch_id, p_sw_stage,
                       p_patch_only_oh = None,
                       p_patch_ojvm = None, p_patch_db_all = None,
                       p_patch_db_list = None, p_patch_item = None):


        self.oracle_home = p_oracle_home
        self.only_prereq = p_only_prereq
        self.patch_id    = p_patch_id
        self.sw_stage    = p_sw_stage
        self.patch_list  = {}
        self.patch_item  = p_patch_item
        self.is_grid     = False

        if not p_only_prereq:

            if p_patch_only_oh == None or p_patch_ojvm == None or p_patch_db_all == None or p_patch_db_list == None:

               fail_module("Specify all required arguments.")

            self.patch_only_oh  = p_patch_only_oh
            self.patch_ojvm     = p_patch_ojvm
            self.patch_db_all   = p_patch_db_all
            self.patch_db_list  = json.loads(p_patch_db_list.strip("['").strip("']"))

        command = "ls " + self.oracle_home + "/bin | grep -iw ohasd.bin | grep -v grep | wc -l"
        output = self.run_os_command(command)
        output = int(output.strip())

        if output == 1:
            self.is_grid = True

        self.oh_version = self.get_oh_version(p_oracle_home)

        if self.oh_version == 11:
            self.gen_ocm_file(p_oracle_home)

    def gen_ocm_file(self, p_oracle_home):
        global g_ocmrf_file
        global g_expected_list
        self.set_env(p_oracle_home)
        command = p_oracle_home + "/OPatch/ocm/bin/emocmrsp -no_banner -output " + g_ocmrf_file
        self.run_os_command(command, p_expect = True)

    def get_oh_version(self, p_oracle_home):
        command = "ls " + p_oracle_home + "/lib | grep libcell.*.so | awk '{ if ($0 == \"libcell11.so\"){ print 11 } if ($0 == \"libcell12.so\") { print 12 } }'"
        output = self.run_os_command(command)
        return int(output.strip())

    def set_env(self, p_ora_home):

        logger("Setting ORACLE_HOME to '" + p_ora_home + "'")
        os.environ["ORACLE_HOME"] = p_ora_home

    def build_patch_dict(self):

        #global patch_list
        v_patch_temp = None

        p_patch_id              = self.patch_item["patch_id"]
        p_patch_proactive_bp_id = self.patch_item["patch_proactive_bp_id"]
        p_patch_gi_id           = self.patch_item["patch_gi_id"]
        p_patch_db_id           = self.patch_item["patch_db_id"]
        p_patch_ocw_id          = self.patch_item["patch_ocw_id"]
        p_patch_ojvm_id         = self.patch_item["patch_ojvm_id"]
        p_patch_dir             = self.patch_item["patch_dir"]
        p_file                  = self.patch_item["file"]
        p_only_oh               = to_bool(self.patch_item["only_oh"])
        p_desc                  = self.patch_item["desc"]
        p_patch_acfs_id         = self.patch_item["patch_acfs_id"]
        p_patch_dbwlm_id        = self.patch_item["patch_dbwlm_id"]

        v_patch_temp = PatchFactory(p_patch_id, p_patch_proactive_bp_id,
                                  p_patch_gi_id, p_patch_db_id, p_patch_ocw_id,
                                  p_patch_ojvm_id, p_patch_acfs_id,
                                  p_patch_dbwlm_id, p_patch_dir,
                                  p_file, p_only_oh, p_desc)

        self.patch_list[p_patch_id] = v_patch_temp

        # If patch is not found throw a fail message.
        if not v_patch_temp:

            fail_module("Patch " + str (self.patch_id) + " not found!")

    def run_os_command(self, p_command, p_expect = False):

        v_error = None
        v_output = ""
        global g_expected_list

        logger("subprocess: " + p_command)

        if p_expect:

            timeout = 3600 # 60 minutes
            #s = pexpect.pxssh()

            #try:

            # Prefer pexpect.run
            v_output, v_error = pexpect.run(p_command.decode(), timeout = timeout, withexitstatus = True, events = g_expected_list)

            #except TypeError:

            #    try:
            #
            #        v_output, v_error = pexpect.runu(p_command.decode(), timeout = timeout, withexitstatus = True, events = g_expected_list)
            #
            #    except:
            #        raise
        else:

            process = subprocess.Popen(p_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            v_output, v_error = process.communicate()


        logger("subprocess output: " + str (v_output))

        if v_error:

            logger("subprocess error: " + str (v_error))
            fail_module(v_error)

        else:

            return str (v_output)


    def check_opatch_min_version(self):

        global g_sw_opatch_min_version

        v_oracle_home   = str (self.oracle_home)
        v_sw_stage      = str (self.sw_stage)

        for patch in self.patch_list:

            v_patch_obj = self.patch_list[patch]

            logger("Check minumum OPatch version for OH: " + self.oracle_home)

            v_patch_dir = v_patch_obj.patch_dir
            v_patch_proactive_bp_id = v_patch_obj.patch_proactive_bp_id
            v_patch_gi_id = v_patch_obj.patch_gi_id
            v_patch_db_id = v_patch_obj.patch_db_id
            v_patch_id = v_patch_obj.patch_id
            v_is_combo = v_patch_obj.is_combo

            v_command = v_oracle_home + "/OPatch/opatch prereq CheckMinimumOPatchVersion -phBaseDir " + v_sw_stage + "/" + v_patch_dir

            if v_is_combo:
                if v_patch_proactive_bp_id:
                    v_command += "/" + str (v_patch_proactive_bp_id) + "/" + str (v_patch_db_id)
                elif v_patch_gi_id:
                    v_command += "/" + str (v_patch_gi_id) + "/" + str (v_patch_db_id)
            else:
                v_command += "/" + str (v_patch_db_id)

            #ToDo: when patching only OJVM

            output = self.run_os_command(v_command)

            if re.search(g_sw_opatch_min_version,output) is None:

                p_message = "CheckMinimumOPatchVersion failed for " + self.oracle_home
                fail_module(p_message)

    def check_conflict_against_oh(self):

        global g_sw_opatch_check_conflict_pattern
        global g_sw_opatch_spacecheck_pattern

        v_oracle_home   = str (self.oracle_home)
        v_sw_stage      = str (self.sw_stage)

        for patch in self.patch_list:

            v_patch_obj = self.patch_list[patch]

            logger("Check conflict for patch: " + v_patch_obj.desc)

            v_patch_dir = v_patch_obj.patch_dir
            v_patch_proactive_bp_id = v_patch_obj.patch_proactive_bp_id
            v_patch_gi_id = v_patch_obj.patch_gi_id
            v_patch_db_id = v_patch_obj.patch_db_id
            v_patch_ocw_id = v_patch_obj.patch_ocw_id
            v_patch_dbwlm_id = v_patch_obj.patch_dbwlm_id
            v_patch_acfs_id = v_patch_obj.patch_acfs_id
            v_patch_id = v_patch_obj.patch_id
            v_is_combo = v_patch_obj.is_combo

            v_command_list = {}

            v_base_path_conflict = v_oracle_home + "/OPatch/opatch prereq CheckConflictAgainstOHWithDetail -phBaseDir " + v_sw_stage + "/" + v_patch_dir
            v_base_path_space = v_oracle_home + "/OPatch/opatch prereq CheckSystemSpace -phBaseDir " + v_sw_stage + "/" + v_patch_dir

            if v_is_combo:
                if v_patch_proactive_bp_id:
                    v_base_path_conflict += "/" + str (v_patch_proactive_bp_id)
                    v_base_path_space += "/" + str (v_patch_proactive_bp_id)
                elif v_patch_gi_id:
                    v_base_path_conflict += "/" + str (v_patch_gi_id)
                    v_base_path_space += "/" + str (v_patch_gi_id)

            if v_patch_db_id:
                v_command_list["conflict_db"] = v_base_path_conflict + "/" + str (v_patch_db_id)
                v_command_list["space_db"] = v_base_path_space + "/" + str (v_patch_db_id)

            if v_patch_ocw_id:
                v_command_list["conflict_ocw"] = v_base_path_conflict + "/" + str (v_patch_ocw_id)
                v_command_list["space_ocw"] = v_base_path_space + "/" + str (v_patch_ocw_id)

            if v_patch_dbwlm_id:
                v_command_list["conflict_dbwlm"] = v_base_path_conflict + "/" + str (v_patch_dbwlm_id)
                v_command_list["space_dbwlm"] = v_base_path_space + "/" + str (v_patch_dbwlm_id)

            if v_patch_acfs_id:
                v_command_list["conflict_acfs"] = v_base_path_conflict + "/" + str (v_patch_acfs_id)
                v_command_list["space_acfs"] = v_base_path_space + "/" + str (v_patch_acfs_id)


            for command in v_command_list:

                output = self.run_os_command(v_command_list[command])

                if command[:8] == "conflict" and re.search(g_sw_opatch_check_conflict_pattern,output) is None:

                    p_message = "CheckConflictAgainstOHWithDetail failed for " + self.oracle_home
                    fail_module(p_message)

                elif command[:5] == "space" and re.search(g_sw_opatch_spacecheck_pattern,output) is None:

                    p_message = "CheckSystemSpace failed for " + self.oracle_home
                    fail_module(p_message)

    def patch_oh(self):

        # start: "if self.is_grid"
        if self.is_grid:

            self.patch_grid_oh()

        else:

            self.patch_db_oh()

    # end: patch_oh

    def patch_db(self, p_ojvm = False):

        if self.patch_db_all:

            logger("Patch all databases for ORACLE_HOME: " + self.oracle_home)

        else:

            logger("Patch specific databases for ORACLE_HOME: " + self.oracle_home)

            if not g_instance_list:
                logger("Specified databases were not found!",True)
            else:

                for item in g_instance_list:
                    logger("database: " + g_instance_list[item].name,True)

        #db_list_to_patch = active_instance_list

        for dbname in g_instance_list:

            v_db_obj = g_instance_list[dbname]

            if v_db_obj.is_standby:

                logger("Database " + v_db_obj.db_name + " was not patched because it's standby database.",True)
                continue

            if v_db_obj.initial_state == "OPEN":

                if v_db_obj.version_short == 12:
                    self.patch_db_12c(v_db_obj, p_ojvm)

                elif (v_db_obj.version_short == 11) or (v_db_obj.version_short == 10):
                    self.patch_db_pre_12c(v_db_obj, p_ojvm)

            else:

                logger("Database " + v_db_obj.name + " was not patched because its initial state was " + v_db_obj.initial_state + ".",True)

    def patch_db_pre_12c(self, p_db_obj, p_ojvm):

        #if self.patch_db_id:
        #logger("starting instance: " + p_db_obj.sid)

        self.start_instance(p_db_obj.sid)

        command = "export ORACLE_SID=" + p_db_obj.sid + "; " + self.oracle_home + "/bin/sqlplus / as sysdba <<< \"@" + self.oracle_home + "/rdbms/admin/catbundle.sql psu apply\""
        logger("Now to patch PSU database data dictionary: \"" + p_db_obj.sid + "\"", True)
        output = self.run_os_command(command)
        logger(output)

        self.stop_instance(p_db_obj.sid)

        if p_ojvm and self.patch_ojvm_id:

            self.start_instance(p_db_obj.sid, "upgrade")

            command = "export ORACLE_SID=" + p_db_obj.sid + "; " + self.oracle_home + "/bin/sqlplus / as sysdba <<< \"@" + self.oracle_home + "/sqlpatch/" + self.patch_ojvm_id + "/postinstall.sql\""
            logger("Now to patch OJVM database data dictionary: """ + p_db_obj.sid + "", True)
            output = self.run_os_command(command)
            logger(output)

            self.stop_instance(p_db_obj.sid)


    def patch_db_12c(self, p_db_obj, p_ojvm):

        if p_ojvm:
            self.start_instance(p_db_obj.sid, "upgrade")
        else:
            self.start_instance(p_db_obj.sid)

        v_command = "export ORACLE_SID=" + p_db_obj.sid + "; $ORACLE_HOME/OPatch/datapatch -verbose"

        logger("Now to patch database: \"" + p_db_obj.sid + "\"", True)

        v_output = self.run_os_command(v_command)

        logger(v_output)

        self.stop_instance(p_db_obj.sid)

    def patch_grid_oh(self):

        v_sw_stage = str (self.sw_stage)
        global g_ocmrf_file

        for item in self.patch_list:

            v_patch_obj = self.patch_list[item]

            v_patch_proactive_bp_id = str (v_patch_obj.patch_proactive_bp_id)
            v_patch_gi_id = str (v_patch_obj.patch_gi_id)
            v_patch_dir = v_patch_obj.patch_dir

            if self.oh_version == 12:

                # COMBO of OJVM + DBBP
                if v_patch_obj.is_dbbp and v_patch_obj.is_combo:
                    v_path = self.oracle_home + "/OPatch/opatchauto apply " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_proactive_bp_id + " -oh " + self.oracle_home

                # DBBP only
                if v_patch_obj.is_dbbp and not v_patch_obj.is_combo:
                    v_path = self.oracle_home + "/OPatch/opatchauto apply " + v_sw_stage + "/" + v_patch_dir + " -oh " + self.oracle_home


            if self.oh_version == 11:

                # COMBO of OJVM + GI
                if v_patch_obj.is_combo:
                    v_path = self.oracle_home + "/OPatch/opatch auto " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_gi_id + " -oh " + self.oracle_home + " -ocmrf " + g_ocmrf_file

                # GI only, in such case v_patch_dir == v_patch_gi_id
                if not v_patch_obj.is_combo:
                    v_path = self.oracle_home + "/OPatch/opatch auto " + v_sw_stage + "/" + v_patch_dir + " -oh " + self.oracle_home + " -ocmrf " + g_ocmrf_file


            if g_root_password:
                v_command = "su -c \"" + v_path + "\""
                g_expected_list["Password: ".decode()] = g_root_password + "\r".decode()
                v_output= self.run_os_command(v_command, p_expect = True)
            else:
                v_command = "sudo " + v_path
                v_output= self.run_os_command(v_command)

            if self.oh_version == 12:
                if re.search(g_sw_opatchauto_check_pattern12, v_output) is not None:
                    g_changed = True
                    return

            if self.oh_version == 11:
                if re.search(g_sw_opatchauto_check_pattern11, v_output) is not None:
                    g_changed = True
                    return

            if re.search(g_sw_opatch_no_need, v_output) is not None:
                return
            else:
                fail_module("Error during applying patch for: " + self.oracle_home)


    def patch_oh_ojvm(self):

        v_sw_stage = str (self.sw_stage)
        v_patch_id = str (self.patch_id)

        for item in self.patch_list:

            v_patch_obj = self.patch_list[item]

            v_patch_proactive_bp_id = str (v_patch_obj.patch_proactive_bp_id)
            v_patch_dir             = v_patch_obj.patch_dir
            v_patch_ojvm_id           = str (v_patch_obj.patch_ojvm_id)

            if v_patch_obj.is_combo:
                v_command = self.oracle_home + "/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_ojvm_id

            output= self.run_os_command(v_command)

            if re.search(g_sw_opatch_check_pattern1,output) is not None or re.search(g_sw_opatch_check_pattern2,output) is not None:
                g_changed = True

            elif re.search(g_sw_opatch_no_need,output) is not None:
                pass

            else:
                fail_module("Error during applying patch for: " + self.oracle_home)

    def patch_db_oh(self):

        v_sw_stage = str (self.sw_stage)
        v_patch_id = str (self.patch_id)

        for item in self.patch_list:

            v_patch_obj = self.patch_list[item]

            v_patch_proactive_bp_id = str (v_patch_obj.patch_proactive_bp_id)
            v_patch_db_id           = str (v_patch_obj.patch_db_id)
            v_patch_dir             = v_patch_obj.patch_dir


            # If patch is DBBP only
            if v_patch_obj.is_dbbp and not v_patch_obj.is_combo:
                # If the patch is DBBP only, v_patch_dir == v_patch_proactive_bp_id
                v_command = self.oracle_home+"/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_db_id

            # If patch is COMBO of OJVM + DBBP
            if v_patch_obj.is_dbbp and v_patch_obj.is_combo:
                v_command = self.oracle_home+"/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_proactive_bp_id + "/" + v_patch_db_id

            # If patch is COMBO of OJVM + DB PSU
            if not v_patch_obj.is_dbbp and v_patch_obj.is_combo:
                v_command = self.oracle_home+"/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_db_id

            # If patch is GI PSU (includes DB PSU)
            if v_patch_obj.is_grid:
                v_command = self.oracle_home+"/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir + "/" + v_patch_db_id

            else:
                v_command = self.oracle_home+"/OPatch/opatch apply -silent " + v_sw_stage + "/" + v_patch_dir

            if self.oh_version == 11:
                v_command += " -ocmrf " + g_ocmrf_file

            output= self.run_os_command(v_command)

            if re.search(g_sw_opatch_check_pattern1,output) is not None or re.search(g_sw_opatch_check_pattern2,output) is not None:
                g_changed = True

            elif re.search(g_sw_opatch_no_need,output) is not None:
                pass

            else:
                fail_module("Error during applying patch for: " + self.oracle_home)

    #def patch_rac_oh(self):

    def stop_services_from_oh(self):

        global g_instance_list

        # Stop active listeners
        for item in g_listener_list:

            self.set_env(item.oracle_home)
            self.stop_listener(item.listener_name)

        # Stop active instances from specified OH
        for item in g_instance_list:

            v_db_obj = g_instance_list[item]

            if not v_db_obj.is_asm:

                self.set_env(v_db_obj.oracle_home)
                self.stop_instance(v_db_obj.sid)

        # Stop active ASM instances from specified OH
        for item in g_instance_list:

            v_db_obj = g_instance_list[item]

            if v_db_obj.is_asm:

                self.set_env(v_db_obj.oracle_home)
                self.stop_instance(v_db_obj.sid, p_asm = True)

    def start_services_from_oh(self):

        global g_instance_list

        # Start previously stopped ASM instances
        for item in g_instance_list:

            v_db_obj = g_instance_list[item]

            if v_db_obj.is_asm:

                self.set_env(g_instance_list[item].oracle_home)
                self.start_instance(g_instance_list[item].sid, p_asm = True)

        #logger("Now starting: [instance_list]: " + str (g_instance_list))
        # Start previously stopped DB instances
        for item in g_instance_list:

            v_db_obj = g_instance_list[item]
            #logger("Now starting: [db_name]: " + str (v_db_obj.name))
            #logger("Now starting: [initial_state]: " + str (v_db_obj.initial_state))
            #logger("Now starting  [is_asm]: " + str (v_db_obj.is_asm))
            if not v_db_obj.is_asm:

                v_db_obj = g_instance_list[item]
                self.set_env(v_db_obj.oracle_home)

                if v_db_obj.initial_state == "OPEN":

                    self.start_instance(v_db_obj.sid, "open")

                elif v_db_obj.initial_state == "MOUNTED":

                    self.start_instance(v_db_obj.sid, "mount")

        # Start previously stopped listeners
        for item in g_listener_list:

            self.set_env(item.oracle_home)
            self.start_listener(item.listener_name)

    def build_instance_list(self):

        global g_file_oratab
        v_oratab_sid_match = {}
        v_oratab_asm_sid_match = {}
        v_oratab_sid_list = {}

        # Build list of DBs defined in oratab
        f = open(g_file_oratab,'r')
        lines_oratab = list(f)

        for line in lines_oratab:

            if not line.startswith('#') and not line.startswith('\n'):

                line_elements = line.split(':')
                v_oratab_sid_list[line_elements[0]] = line_elements[1]

        f.close

        # Build list of DBs from oratab which map to specified OH
        for item in v_oratab_sid_list:

            if v_oratab_sid_list[item] == self.oracle_home:

                if self.is_grid:

                    v_oratab_asm_sid_match[item] = v_oratab_sid_list[item]
                else:

                    v_oratab_sid_match[item] = v_oratab_sid_list[item]

        # If OH is GI
        if self.is_grid:

            # Get 1st key from "v_oratab_asm_sid_match"
            #   - since it's GI, we're assuming only one ASM per GI.
            v_asm_sid = v_oratab_asm_sid_match.keys()[0]

            # Check if ASM is running
            command = "ps -ef | grep -iw asm_pmon_" + v_asm_sid + " | grep -v grep | wc -l"
            output = self.run_os_command(command)
            v_is_sid_active = int(output.strip())

            # If ASM instance is running
            if v_is_sid_active:

                # Create DB object for ASM instance
                self.create_db_object(v_asm_sid, self.oracle_home, True)

                # Set OH to GI
                self.set_env(self.oracle_home)

                # Get ASM clients
                #   - if patching GI OH, add ASM clients to "oratab_sid_match" which needs to be stopped.
                command = "export ORACLE_SID=""" + v_asm_sid + "; $ORACLE_HOME/bin/sqlplus -s / as sysdba @/tmp/orapatch_scripts/get_asm_clients"
                asm_clients = self.run_os_command(command).strip().split(';')
                # remove index 0 - used to catch output from gloging.sql
                asm_clients.pop(0)

                for client in asm_clients:

                    v_db_name = client.split(',')[0]
                    v_inst_name = client.split(',')[1]

                    # If ASM client matches to oratab list
                    if v_inst_name not in v_oratab_sid_match:

                        v_oratab_sid_match[v_inst_name] = v_oratab_sid_list[v_inst_name]


        #
        # 1. patch_only OH
        #   -shutdown/start up ONLY active instances

        # 2. patch all DBs
        #   -shutdown/start up all active and inactive instances

        # 3. patch specific DBs
        #   -shutdown/start up only specific instances

        if self.patch_only_oh or self.patch_db_all:

            for sid in v_oratab_sid_match:

                v_command = "ps -ef | grep -iw ora_pmon_" + sid + " | grep -v grep | wc -l"

                v_output = self.run_os_command(v_command)
                v_is_sid_active = int(v_output.strip())

                if v_is_sid_active == 1:

                    self.create_db_object(sid,v_oratab_sid_match[sid])

        elif not self.patch_only_oh and not self.patch_db_all and self.patch_db_list:


            for sid in v_oratab_sid_match:

                # 1. "sid in self.patch_db_list"
                    # If the instance from oratab list is found
                    # in user specified list, create DB object

                # 2. "v_oratab_sid_match[sid] == self.oracle_home:"
                    # If the instance from oratab list is not found
                    # in user specified list, but it has same OH which will
                    # be patched, crete DB object
                if (sid in self.patch_db_list) or (v_oratab_sid_match[sid] == self.oracle_home):

                    v_command = "ps -ef | grep -iw ora_pmon_" + sid + " | grep -v grep | wc -l"
                    v_output = self.run_os_command(v_command)
                    v_is_sid_active = int(v_output.strip())

                    # If the instance is running then create DB object
                    # otherwise DB object is not needed, since the DB is down.
                    if v_is_sid_active == 1:
                        self.create_db_object(sid,v_oratab_sid_match[sid])

            #end for loop

        else:

            fail_module("Invalid options specified!")

    def create_db_object(self, p_sid, p_ora_home, p_asm = False):

        global g_instance_list

        v_db_initial_state = None

        self.set_env(p_ora_home)

        if not p_asm:
            # get db metadata
            v_command = "export ORACLE_SID=""" + p_sid + "; $ORACLE_HOME/bin/sqlplus -s / as sysdba @/tmp/orapatch_scripts/get_db_metadata"

            v_db_metadata = self.run_os_command(v_command).strip().split(';')

            # remove index 0 - used to catch output from gloging.sql
            v_db_metadata.pop(0)

            v_db_name = v_db_metadata[0]

            v_db_version = v_db_metadata[1]

            if v_db_metadata[2] == 'PHYSICAL STANDBY':

                v_db_is_standby = True

            else:

                v_db_is_standby = False

            v_db_is_rac = to_bool(v_db_metadata[3])

            if v_db_is_rac:

                v_db_inst_list = v_db_metadata[4].split(',')

            else:

                v_db_inst_list = v_db_metadata[4]

            v_db_initial_state = v_db_metadata[5]

        else:

            # get db metadata
            v_command = "export ORACLE_SID=""" + p_sid + "; $ORACLE_HOME/bin/sqlplus -s / as sysasm @/tmp/orapatch_scripts/get_asm_metadata"
            v_db_metadata = self.run_os_command(v_command).strip().split(';')

            # remove index 0 - used to catch output from gloging.sql
            v_db_metadata.pop(0)

            v_db_name = None
            v_db_version = v_db_metadata[1]
            v_db_is_standby = False
            v_db_is_rac = to_bool(v_db_metadata[2])

            if v_db_is_rac:

                v_db_inst_list = v_db_metadata[3].split(',')

            else:

                v_db_inst_list = v_db_metadata[3]


            v_db_initial_state = v_db_metadata[4]


        db_obj = DatabaseFactory(p_sid, v_db_version, v_db_name, p_asm, v_db_is_rac
                                ,v_db_is_standby, v_db_inst_list, False
                                ,v_db_initial_state, p_ora_home)

        g_instance_list[p_sid] = db_obj

        #if is_down:
        #    self.stop_instance(p_sid)

        #logger ("db_name: " + db_obj.name)
        #logger ("db_version: " + db_obj.version)
        #logger ("is_standby: " + str (db_obj.is_standby))
        #logger ("is_rac: " + str (db_obj.is_rac))
        #logger ("inst_list: " + db_obj.instance_list)
        #logger ("is_active: " + str (db_obj.is_active))

    def build_listener_list(self, p_oracle_home):

        global g_listener_list

        # the shell command
        v_command = "ps -eo args | grep tns | grep -iw " + p_oracle_home + " | grep -v grep | cut -d' ' -f2"

        #Launch the shell command:
        v_output = self.run_os_command(v_command)

        for listener in v_output.splitlines():
            v_listener_obj = ListenerFactory(listener.strip(), p_oracle_home)
            g_listener_list[v_listener_obj] = v_listener_obj

        #logger("manage: " + str (g_listener_list))

    def stop_instance(self, p_sid, p_mode = "immediate", p_asm = False):

        if p_asm:

            if self.oh_version == 12:
                v_command = "$ORACLE_HOME/bin/srvctl stop asm -f -stopoption " + p_mode
            elif self.oh_version == 11:
                v_command = "$ORACLE_HOME/bin/srvctl stop asm -f -o " + p_mode

        else:
            v_command = "export ORACLE_SID=" + p_sid + "; $ORACLE_HOME/bin/sqlplus -s / as sysdba <<< \"shutdown " + p_mode + "\""

        logger("Stopping instance: " + p_sid)

        return self.run_os_command(v_command)

    def stop_listener(self, p_listener):

        v_command = "$ORACLE_HOME/bin/lsnrctl stop " + p_listener

        logger("Stopping listener: " + p_listener)

        return self.run_os_command(v_command)

    def start_instance(self, p_sid, p_mode = "open", p_asm = False):


        if p_asm:

            v_command = "$ORACLE_HOME/bin/srvctl start asm"

        else:

            v_command = "export ORACLE_SID=" + p_sid + "; $ORACLE_HOME/bin/sqlplus -s / as sysdba <<< \"startup " + p_mode + "\""

        logger("Starting instance: " + p_sid)

        return self.run_os_command(v_command)

    def start_listener(self, p_listener):

        v_command = "$ORACLE_HOME/bin/lsnrctl start " + p_listener

        logger("Starting listener: " + p_listener)

        return self.run_os_command(v_command)

    def check_running_services_from_oh(self):

        global g_instance_list

        v_fail = False

        if not self.is_grid:
            # Check running processes from OH
            v_command = "ps -ef | grep -iw " + self.oracle_home + " | grep -v grep | wc -l"
            #Launch the shell command:
            v_output = self.run_os_command(v_command)

            v_output = int(v_output.strip())

            if v_output > 0:

                v_fail = True

        for item in g_instance_list:

            v_db_obj = g_instance_list[item]

            if v_db_obj.initial_state != "DOWN":

                if v_db_obj.is_asm:

                    v_command = "ps -ef | grep -iw asm_pmon_" + v_db_obj.sid + " | grep -v grep | wc -l"

                else:

                    v_command = "ps -ef | grep -iw ora_pmon_" + v_db_obj.sid + " | grep -v grep | wc -l"

                #Launch the shell command:
                v_output = self.run_os_command(v_command)

                v_output = int(v_output.strip())

                if v_output > 0:

                    v_fail = True

        #if not found_home_oratab:
            #module.fail_json(rc=256, msg="Oracle home " + self.oracle_home+" was not found in " + g_file_oratab)
        #    p_message = "Oracle home " + self.oracle_home+" was not found in " + g_file_oratab
        #    fail_module(p_message)
        if v_fail:
            #module.fail_json(rc=256, msg="There are active services under " + self.oracle_home)
            p_message = "There are running processes under " + self.oracle_home

            fail_module(p_message)


    def patchprocess_pre_patch(self):

        logger("==============================================",True)
        logger(g_function + " => BUILD_INSTANCE_LIST",True)
        logger("==============================================",True)
        self.build_instance_list()

        logger("==============================================",True)
        logger(g_function + " => BUILD_LISTENER_LIST",True)
        logger("==============================================",True)
        for item in g_instance_list:
            inst = g_instance_list[item]
            self.build_listener_list(inst.oracle_home)

        logger("==============================================",True)
        logger(g_function + " => STOP_SERVICES_FROM_OH",True)
        logger("==============================================",True)
        self.stop_services_from_oh()

        logger("==============================================",True)
        logger(g_function + " => CHECK_RUNNING_SERVICES_FROM_OH",True)
        logger("==============================================",True)
        self.check_running_services_from_oh();


    def patchprocess_post_patch(self):

        logger("==============================================",True)
        logger(g_function + " => START_SERVICES_FROM_OH",True)
        logger("==============================================",True)
        self.start_services_from_oh()


    def patchprocess_main(self):

        # Build list of patches which will be applied
        self.build_patch_dict()

        v_patch_obj = self.patch_list[self.patch_id]

        if self.is_grid and not pexpect_found:
            fail_module("Trying to patch GI home without having \"pexpect\" module.")

        if g_function == "CHECK_OPATCH_MIN_VERSION":

            logger("==============================================",True)
            logger("FUNC => CHECK_OPATCH_MIN_VERSION",True)
            logger("==============================================",True)
            self.check_opatch_min_version()

        elif g_function == "CHECK_CONFLICT_AGAINST_OH":

            logger("==============================================",True)
            logger("FUNC => CHECK_CONFLICT_AGAINST_OH",True)
            logger("==============================================",True)
            self.check_conflict_against_oh()
            g_changed = False

        elif g_function == "PATCH_OH" and not self.only_prereq:

            self.patchprocess_pre_patch()

            logger("==============================================",True)
            logger("FUNC => PATCH_OH",True)
            logger("==============================================",True)
            self.patch_oh()

            self.patchprocess_post_patch()

        elif g_function == "PATCH_DB" and not self.patch_only_oh and not v_patch_obj.only_oh and not self.is_grid:

            self.patchprocess_pre_patch()

            logger("==============================================",True)
            logger("FUNC => PATCH_DB",True)
            logger("==============================================",True)
            self.patch_db()

            self.patchprocess_post_patch()

        elif g_function == "PATCH_OH_OJVM" and not self.patch_only_oh and not v_patch_obj.only_oh and not self.is_grid:

            self.patchprocess_pre_patch()

            logger("==============================================",True)
            logger("FUNC => PATCH_OH_OJVM",True)
            logger("==============================================",True)
            self.patch_oh_ojvm()

            self.patchprocess_post_patch()

        elif g_function == "PATCH_DB_OJVM" and not self.patch_only_oh and not v_patch_obj.only_oh and not self.is_grid:

            self.patchprocess_pre_patch()

            logger("==============================================",True)
            logger("FUNC => PATCH_DB_OJVM",True)
            logger("==============================================",True)
            self.patch_db(p_ojvm = True)

            self.patchprocess_post_patch()

def main():

    global module
    global g_function
    global g_logger_file
    global g_root_password
    global g_file_oratab

    module = AnsibleModule(
        argument_spec = dict(
            oracle_home         = dict(required = True,  type = 'path'),
            swlib_path          = dict(required = True,  type = 'path'),
            patch_id            = dict(required = True,  type = 'int'),
            only_prereq         = dict(required = True,  type = 'bool'),
            patch_only_oh       = dict(required = False, type = 'bool'),
            patch_ojvm          = dict(required = False, type = 'bool'),
            patch_db_all        = dict(required = False, type = 'bool'),
            patch_db_list       = dict(required = False, type = 'str'),
            patch_item          = dict(required = True,  type = 'dict'),
            function            = dict(required = True,  type = 'str'),
            orapatch_logfile    = dict(required = True,  type = 'str'),
            root_password       = dict(required = True,  type = 'str'),
            oratab_file         = dict(required = False,  type = 'str')
        )
    )

    # Define arguments passed from ansible playbook.
    p_oracle_home   = module.params['oracle_home']
    p_sw_stage      = module.params['swlib_path']
    p_patch_id      = module.params['patch_id']
    p_only_prereq   = module.params['only_prereq']
    p_patch_only_oh = module.params['patch_only_oh']
    p_patch_ojvm    = module.params['patch_ojvm']
    p_patch_db_all  = module.params['patch_db_all']
    p_patch_db_list = module.params['patch_db_list']
    p_patch_item    = module.params['patch_item']
    g_logger_file   = module.params['orapatch_logfile']
    g_function      = module.params['function'].upper()
    g_root_password = module.params['root_password']
    g_file_oratab   = module.params['oratab_file']

    #if g_function != "START_LOGGER_SESSION" and g_function != "END_LOGGER_SESSION":
    #    logger(g_function)
    #    logger("here: " + str (g_file_oratab))
    #    fail_module(g_root_password)

    if g_function == "START_LOGGER_SESSION":

        start_logger_session()

    elif g_function == "END_LOGGER_SESSION":

        end_logger_session()

    else:

        patchprocess = PatchProcess(p_oracle_home, p_only_prereq, p_patch_id
                                    ,p_sw_stage, p_patch_only_oh, p_patch_ojvm
                                    ,p_patch_db_all, p_patch_db_list
                                    ,p_patch_item)

        patchprocess.patchprocess_main()

    module.exit_json(changed = g_changed, msg = "Finished.")

if __name__ == '__main__':

    main()
