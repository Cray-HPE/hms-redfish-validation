#!/usr/bin/python3

# MIT License
#
# (C) Copyright [2022] Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

"""
Driver for validation
"""

from datetime import datetime

import os
from os import walk
import pathlib
import sys
import argparse
import json
import logging
import subprocess
import getpass
import re

my_logger = logging.getLogger()
my_logger.setLevel(logging.INFO)

std_out = logging.StreamHandler(sys.stdout)
std_out.setLevel(logging.INFO)
my_logger.addHandler(std_out)

VERSION="0.1.0"

# Validation targets
PR1_SUSTAINED_RATE_MINIMUM = 30     # per second
PR2_PEAK_RATE_MINIMUM = 100         # per second
PR4_MAX_CALL_TIME = 30.0            # seconds compared against avg call time

PROFILE_PATH='sub/redfish-validator-profiles/profiles'

def load_arguments(opts: dict, args: dict) -> dict:
    """
    Load arguments from the command line. These will override any arguments set
    from a json file passed in.
    """

    if args.verbose:
        opts['verbose'] = args.verbose

    if args.list:
        opts['list'] = args.list

    if args.tests is not None and len(args.tests) > 0:
        opts['tests'] = []
        opts['tests'].extend(args.tests.split(','))
        opts['tests'] = list(set(opts['tests']))

    if args.hosts is not None and len(args.hosts) > 0:
        opts['hosts'] = []
        opts['hosts'].extend(args.hosts.split(','))
        opts['hosts'] = list(set(opts['hosts']))

    if args.user is not None:
        opts['user'] = args.user

    if args.passwd is not None:
        opts['passwd'] = args.passwd

    if args.logdir is not None:
        opts['logdir'] = args.logdir

    if args.rpm is not None and args.rpm > 0:
        opts['rpm'] = args.rpm

    if args.runtime is not None and args.runtime > 0:
        opts['runtime'] = args.runtime

    if args.walk_count is not None and args.walk_count > 0:
        opts['walk_count'] = args.walk_count

    if args.port is not None:
        opts['port'] = args.port

    if args.listenip is not None:
        opts['listenip'] = args.listenip

    if args.profile is not None:
        opts['profile'] = args.profile

    return opts


def rf_validation(opts: dict, host: str):
    """
    Launch Redfish Interop Validator
    """
    my_logger.info("Building rfvalidate container...")
    try:
        proc = subprocess.run(['podman-compose', 'build', 'rfvalidate'], check=True,
            capture_output=True)
    except subprocess.CalledProcessError as err:
        my_logger.error(err)
        return 1

    my_logger.debug(proc.stdout.decode())

    passwd = f'-e PASSWD={opts["passwd"]}'
    endpoint = f'-e ENDPOINT={host}'
    profile = f'-e PROFILE={opts["profile"]}'

    my_logger.info("Executing rfvalidate test...")
    try:
        proc = subprocess.run(['podman-compose', 'run', passwd, endpoint,
            profile, 'rfvalidate'], check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        error_output = err.output.decode('utf-8').splitlines()
        power_cap_errors = 0
        error_strings = []
        for line in error_output:
            match = re.search("error|fail", line)
            if match:
                my_logger.debug("- %s", line)

            if re.search(r"\d fail.Control.ReadRequirement", line):
                my_logger.debug("Missing Olympus style power capping")
                power_cap_errors += 1
            if re.search(r"\d fail.Name.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Control Name")
            if re.search(r"\d fail.SetPoint.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Control SetPoint")
            if re.search(r"\d fail.SettingRangeMax.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Control SettingRangeMax")
            if re.search(r"\d fail.SettingRangeMin.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Control SettingRangeMin")
            if re.search(r"\d fail.PhysicalContext.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Control PhysicalContext")
            if re.search(r"\d fail.Reading.ReadRequirement .*Control.*$", line):
                error_strings.append("Missing Sensor Reading")

            if re.search(r"\d fail.HpeServerAccPowerLimit.ReadRequirement", line):
                my_logger.debug("Missing HPE style power capping")
                power_cap_errors += 1
            if re.search(r"\d fail.PowerLimitInWatts.ReadRequirement .*ActualPowerLimits.*$", line):
                error_strings.append("Missing HPE ActualPowerLimits PowerLimitInWatts")
            if re.search(r"\d fail.MaximumPowerLimit.ReadRequirement .*PowerLimitRanges.*$", line):
                error_strings.append("Missing HPE PowerLimitRanges MaximumPowerLimit ")
            if re.search(r"\d fail.MinimumPowerLimit.ReadRequirement .*PowerLimitRanges.*$", line):
                error_strings.append("Missing HPE PowerLimitRanges MinimumPowerLimit Reading")
            if re.search(r"\d fail.PowerLimitInWatts.ReadRequirement .*PowerLimits.*$", line):
                error_strings.append("Missing HPE PowerLimits PowerLimitInWatts")

            if re.search(r"\d fail.PowerControl.ReadRequirement", line):
                my_logger.debug("Missing standard power capping")
                power_cap_errors += 1
            if re.search(r"\d fail.PowerCapacityWatts.ReadRequirement .*PowerControl.*$", line):
                error_strings.append("Could not read PowerControl PowerCapacityWatts")
            if re.search(r"\d fail.LimitInWatts.ReadRequirement .*PowerLimit.*$", line):
                error_strings.append("Could not read PowerLimit LimitInWatts")

            if re.search(r"\d fail.Manager.ReadRequirement", line):
                error_strings.append("Missing Manager")
            if re.search(r"\d fail.ResetType.ReadRequirement .*Managers.*$", line):
                error_strings.append("Could not read Manager ResetType")
            if re.search(r"\d fail.Name.ReadRequirement .*Managers.*$", line):
                error_strings.append("Could not read Manager Name")
            if re.search(r"\d fail.Health.ReadRequirement .*Managers.*$", line):
                error_strings.append("Could not read Manager Health")

            if re.search(r"\d fail.Chassis.ReadRequirement", line):
                error_strings.append("Missing Chassis")
            if re.search(r"\d fail.Manufacturer.ReadRequirement .*Chassis.*$", line):
                error_strings.append("Could not read Chassis Manufacturer name")
            if re.search(r"\d fail.State.ReadRequirement .*Chassis.*$", line):
                error_strings.append("Could not read Chassis State")
            if re.search(r"\d fail.Health.ReadRequirement .*Chassis.*$", line):
                error_strings.append("Could not read Chassis Health")

            if re.search(r"\d fail.Description.ReadRequirement .*EthernetInterfaces.*$", line):
                error_strings.append("Could not read EthernetInterface Description")
            if re.search(r"\d fail.Id.ReadRequirement .*EthernetInterfaces.*$", line):
                error_strings.append("Could not read EthernetInterface Id")
            if re.search(r"\d fail.InterfaceEnabled.ReadRequirement .*EthernetInterfaces.*$", line):
                error_strings.append("Could not read EthernetInterface InterfaceEnabled")
            if re.search(r"\d fail.MACAddress.ReadRequirement .*EthernetInterfaces.*$", line):
                error_strings.append("Could not read EthernetInterface MACAddress")

            if re.search(r"\d fail.Subscriptions.ReadRequirement .*EventService.*$", line):
                error_strings.append("Could not read EventService Subscriptions")
            if re.search(
                r"\d fail.EventTypesForSubscription.ReadRequirement .*EventService.*", line):
                error_strings.append("Could not read EventService EventTypesforSubscription")

            if re.search(r"\d fail.UpdateService.ReadRequirement", line):
                error_strings.append("Missing UpdateService")
            if re.search(r"\d fail.SimpleUpdate.ReadRequirement .*UpdateService.*$", line):
                error_strings.append("Could not read UpdateService SimpleUpdate")
            if re.search(r"\d fail.FirmwareInventory.ReadRequirement .*UpdateService.*$", line):
                error_strings.append("Could not read UpdateService FirmwareInventory")
            if re.search(r"\d fail.Id.ReadRequirement .*FirmwareInventory.*$", line):
                error_strings.append("Could not read FirmwareInventory Id")
            if re.search(r"\d fail.Version.ReadRequirement .*FirmwareInventory.*$", line):
                error_strings.append("Could not read FirmwareInventory Version")
            if re.search(r"\d fail.Name.ReadRequirement .*FirmwareInventory.*$", line):
                error_strings.append("Could not read FirmwareInventory Name")

            if re.search(r"\d fail.Password.WriteRequirement .*ManagerAccount.*$", line):
                error_strings.append("Could not write ManagerAccount Password")
            if re.search(r"\d fail.UserName.WriteRequirement .*ManagerAccount.*$", line):
                error_strings.append("Could not write ManagerAccount UserName")

            if re.search(r"\d fail.Sessions.ReadRequirement .*SessionService.*$", line):
                error_strings.append("Could not read SessionService Sessions")
            if re.search(r"\d fail.ServiceEnabled.ReadRequirement .*SessionService.*$", line):
                error_strings.append("Could not read SessionService ServiceEnabled")

            if re.search(r"\d fail.Tasks.ReadRequirement .*TaskService.*$", line):
                error_strings.append("Could not read TaskService Tasks")
            if re.search(r"\d fail.ServiceEnabled.ReadRequirement .*TaskService.*$", line):
                error_strings.append("Could not read TaskService ServiceEnabled")
            if re.search(
                r"\d fail.LifeCycleEventOnTaskStateChange.ReadRequirement .*TaskService.*$", line):
                error_strings.append("Could not read TaskService LifeCycleEventOnTaskStateChange")

            if re.search(r"\d fail.Members.MinCount .*Managers$", line):
                error_strings.append("Missing managers collection")
            if re.search(r"\d fail.Members.MinCount .*Chassis$", line):
                error_strings.append("Missing chassis collection")
            if re.search(r"\d fail.Members.MinCount .*Controls$", line):
                error_strings.append("Missing controls collection")
            if re.search(r"\d fail.Members.MinCount .*Systems$", line):
                error_strings.append("Missing systems collection")
            if re.search(r"\d fail.Members.MinCount .*Memory$", line):
                error_strings.append("Missing memory collection")
            if re.search(r"\d fail.Members.MinCount .*Processors$", line):
                error_strings.append("Missing processor collection")
            if re.search(r"\d fail.Members.MinCount .*EthernetInterfaces$", line):
                error_strings.append("Missing Ethernet interfaces collection")
            if re.search(r"\d fail.Members.MinCount .*FirmwareInventory$", line):
                error_strings.append("Missing FirmwareInventory collection")
            if re.search(r"\d fail.Members.MinCount .*Accounts$", line):
                error_strings.append("Missing ManagerAccount collection")

        if power_cap_errors > 2:
            error_strings.append("Power capping controls missin")

        if len(error_strings) > 0:
            for err in error_strings:
                my_logger.error("\t%-40s FAIL", err)
            return 1

    my_logger.info("\tRedfish Interop Validator PASS")

    return 0


def sustained_stress(opts: dict, host: str):
    """
    Launch sustained redfish stress test
    """
    my_logger.info("Building sustained stress container...")
    try:
        proc = subprocess.run(['podman-compose', 'build', 'sustained'],
            check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        my_logger.error(err)
        return 1

    my_logger.debug(proc.stdout.decode())

    user = f'-e USER={opts["user"]}'
    passwd = f'-e PASSWD={opts["passwd"]}'
    endpoint = f'-e ENDPOINT={host}'

    my_logger.info("Executing sustained stress test...")
    try:
        proc = subprocess.run(['podman-compose', 'run', user, passwd, endpoint,
            'sustained'], check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        error_output = err.output.decode('utf-8').splitlines()
        for line in error_output:
            match = re.search("error|fail", line)
            if match:
                my_logger.error(line)
        return 1

    result = proc.stdout.decode('utf-8').splitlines()
    for line in result:
        match1 = re.search("Rate achieved", line)
        if match1:
            rate = re.findall(r'\d+', line)
            pass_fail = 'FAIL'
            if int(rate[0]) >= (PR1_SUSTAINED_RATE_MINIMUM - 1):
                pass_fail = 'PASS'

            my_logger.info("%-40s expected %d req/m - %s",
                line, PR1_SUSTAINED_RATE_MINIMUM, pass_fail)

        match2 = re.search("Max call time", line)
        if match2:
            time = re.findall(r'\d+\.\d+', line)
            pass_fail = 'FAIL'
            if float(time[0]) < PR4_MAX_CALL_TIME:
                pass_fail = 'PASS'

            my_logger.info("%-40s expected < %d sec - %s",
                line, PR4_MAX_CALL_TIME, pass_fail)

        match3 = re.search("Using .* for requests", line)
        if match3:
            my_logger.info(line)

        if not match1 and not match2 and not match3:
            my_logger.debug(line)

    return 0


def peak_stress(opts: dict, host: str):
    """
    Launch peak redfish stress test
    """
    my_logger.info("Building peak stress container...")
    try:
        proc = subprocess.run(['podman-compose', 'build', 'peak'], check=True,
            capture_output=True)
    except subprocess.CalledProcessError as err:
        my_logger.error(err)
        return 1

    my_logger.debug(proc.stdout.decode())

    user = f'-e USER={opts["user"]}'
    passwd = f'-e PASSWD={opts["passwd"]}'
    endpoint = f'-e ENDPOINT={host}'

    my_logger.info("Executing peak stress test...")
    try:
        proc = subprocess.run(['podman-compose', 'run', user, passwd, endpoint,
            'peak'], check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        error_output = err.output.decode('utf-8').splitlines()
        for line in error_output:
            match = re.search("error|fail", line)
            if match:
                my_logger.error(line)
        return 1

    result = proc.stdout.decode('utf-8').splitlines()
    for line in result:
        match1 = re.search("Rate achieved", line)
        if match1:
            rate = re.findall(r'\d+', line)
            pass_fail = 'FAIL'
            if int(rate[0]) >= PR2_PEAK_RATE_MINIMUM:
                pass_fail = 'PASS'

            my_logger.info("%-40s expected %d req/m - %s",
                line, PR2_PEAK_RATE_MINIMUM, pass_fail)

        match2 = re.search("Max call time", line)
        if match2:
            time = re.findall(r'\d+\.\d+', line)
            pass_fail = 'FAIL'
            if float(time[0]) < PR4_MAX_CALL_TIME:
                pass_fail = 'PASS'

            my_logger.info("%-40s expected < %d sec - %s",
                line, PR4_MAX_CALL_TIME, pass_fail)

        match3 = re.search("Using .* for requests", line)
        if match3:
            my_logger.info(line)

        if not match1 and not match2 and not match3:
            my_logger.debug(line)

    return 0


def tree_walk(opts: dict, host: str):
    """
    Launch tree walk stress test
    """
    my_logger.info("Building tree walk stress container...")
    try:
        proc = subprocess.run(['podman-compose', 'build', 'walk'], check=True,
            capture_output=True)
    except subprocess.CalledProcessError as err:
        my_logger.error(err)
        return 1

    my_logger.debug(proc.stdout.decode())

    user = f'-e USER={opts["user"]}'
    passwd = f'-e PASSWD={opts["passwd"]}'
    endpoint = f'-e ENDPOINT={host}'

    my_logger.info("Executing tree walk stress test...")
    try:
        proc = subprocess.run(['podman-compose', 'run', user, passwd, endpoint,
            'walk'], check=True, capture_output=True)
    except subprocess.CalledProcessError as err:
        error_output = err.output.decode('utf-8').splitlines()
        for line in error_output:
            match = re.search("error|fail", line)
            if match:
                my_logger.error(line)
        return 1

    result = proc.stdout.decode('utf-8').splitlines()
    for line in result:
        match1 = re.search("Rate achieved", line)
        if match1:
            rate = re.findall(r'\d+', line)
            pass_fail = 'FAIL'
            if int(rate[0]) >= PR1_SUSTAINED_RATE_MINIMUM:
                pass_fail = 'PASS'

            my_logger.info("%-40s expected %d req/m - %s",
                line, PR1_SUSTAINED_RATE_MINIMUM, pass_fail)

        match2 = re.search("Max call time", line)
        if match2:
            time = re.findall(r'\d+\.\d+', line)
            pass_fail = 'FAIL'
            if float(time[0]) < PR4_MAX_CALL_TIME:
                pass_fail = 'PASS'

            my_logger.info("%-40s expected < %d sec - %s",
                line, PR4_MAX_CALL_TIME, pass_fail)

        match3 = re.search("Reached max", line)
        if match3:
            my_logger.info(line)

        if not match1 and not match2 and not match3:
            my_logger.debug(line)

    return 0


def power_cap(opts: dict):
    """
    Launch power capping test
    """
    my_logger.info("Yup, power capping")
    return 0


def power_control(opts: dict):
    """
    Launch power control test
    """
    my_logger.info("Yup, power control")
    return 0


def streaming_telemetry(opts: dict):
    """
    Launch streaming telemetry test
    """
    my_logger.info("Yup, streaming telemetry")
    return 0


VALFUNC=0
VALREQ=1
VALDEF=2

validations = {
    # key: [ Function, required options, default options ]
    'rfvalidate': [ rf_validation, "", "" ],
    'sustained': [ sustained_stress, "", "" ],
    'peak': [ peak_stress, "--hosts [hostlist]", "none" ],
    'walk': [ tree_walk, "", "" ],
    'power-cap': [ power_cap, "", "" ],
    'power-control': [ power_control, "", "" ],
    'telemetry': [ streaming_telemetry, "", "" ]
}


def main():
    """
    Do stuff
    """
    parser = argparse.ArgumentParser(
        description='HPE tool to validate a Redfish implementation, ' \
            f'version {VERSION}')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbosity of tool in stdout')
    parser.add_argument('-V', '--version', action='store_true', default=0,
                        help='Verbosity of tool in stdout')

    parser.add_argument('-c', '--config', help='')
    parser.add_argument('-l', '--list', action='store_true',
        help='list tests and profiles')
    parser.add_argument('-T', '--tests', help='')
    parser.add_argument('-H', '--hosts', help='')
    parser.add_argument('-U', '--user', help='')
    parser.add_argument('-P', '--passwd', help='')
    parser.add_argument('-o', '--logdir', help='')
    parser.add_argument('-r', '--rpm', type=int, help='')
    parser.add_argument('-t', '--runtime', type=int, help='')
    parser.add_argument('-w', '--walk-count', type=int, help='')
    parser.add_argument('-p', '--port', type=int, help='')
    parser.add_argument('-i', '--listenip', help='')
    parser.add_argument('-f', '--profile', help='')

    args = parser.parse_args()

    if args.version is True:
        print(f'{__file__}: {VERSION}')
        return 0

    start_time = datetime.now()

    if args.verbose is True:
        log_level = logging.DEBUG
        my_logger.setLevel(log_level)
        std_out.setLevel(log_level)

    my_logger.info('Redfish Validation driver')

    if args.logdir is not None:
        logpath = args.logdir

        if not os.path.isdir(logpath):
            os.makedirs(logpath)

        log_file = os.path.join(logpath, 'HMS-Validation_%m_%d_%Y_%H%M%S.txt')
        file_handler = logging.FileHandler(datetime.strftime(start_time, log_file))
        file_handler.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(levelname)s - %(message)s')
        file_handler.setFormatter(fmt)
        my_logger.addHandler(file_handler)
        my_logger.info(' Log file: %s', file_handler.baseFilename)

    my_logger.info('')

    opts = {}

    if args.config is not None:
        try:
            with open(args.config, encoding='utf-8') as config_file:
                opts = json.loads(config_file.read())
        except IOError as io_err:
            my_logger.warning('open() failed %s', io_err)
        except json.JSONDecodeError as json_error:
            my_logger.error('Failed to parse json from config file: %s', json_error)
            sys.exit(1)

    opts = load_arguments(opts, args)
    my_logger.debug(opts)

    if len(opts) == 0:
        my_logger.error('Invalid, no arguments')
        sys.exit(1)

    valid_tests = validations.keys()

    if 'list' in opts and opts['list']:
        my_logger.info('Available tests:')
        for test in valid_tests:
            my_logger.info('\t%-15s\trequired options: %s  defaults: %s', test,
                validations[test][VALREQ], validations[test][VALDEF])
        my_logger.info('')

        my_logger.info('Available profiles:')

        files = []
        for (_, _, fnames) in walk(PROFILE_PATH):
            files.extend(fnames)
            break

        files.sort()
        for file in files:
            if pathlib.Path(file).suffix == '.json':
                my_logger.info('\t%s', pathlib.Path(file).stem)

        return 0

    if 'user' not in opts:
        opts['user'] = input('Enter username for Redfish: ')

    if 'passwd' not in opts:
        opts['passwd'] = getpass.getpass(f'Enter password for {opts["user"]}: ')

    if 'hosts' not in opts or len(opts['hosts']) == 0:
        my_logger.error('Invalid hosts argument.')
        sys.exit(1)

    if 'tests' in opts and len(opts['tests']) > 0:
        if not set(opts['tests']).issubset(valid_tests):
            my_logger.error('Invalid tests argument')
            sys.exit(1)

    for test in opts['tests']:
        for host in opts['hosts']:
            validations[test][VALFUNC](opts, host)

    return 0


if __name__ == '__main__':
    RESULT = main()
    sys.exit(RESULT)
