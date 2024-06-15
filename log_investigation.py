"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib as la
import re

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = la.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    # TODO: Complete function body per step 7
    portsDict = {}

    regex = 'DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    tallyCount, capturedData = la.filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False)
    for record in tallyCount:
        addr = re.findall(regex, record)
        for ip in addr:
            if ip in portsDict:
                portsDict[ip]+=1
            else:
                portsDict[ip]=1
    print(portsDict)

    return portsDict

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    # TODO: Complete function body per step 8
    # Get data from records that contain the specified destination port
    # Generate the CSV report
    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    # Get data from records that show attempted invalid user login
    # Generate the CSV report
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    # Get all records that have the specified sourec IP address
    # Save all records to a plain text .log file
    return

if __name__ == '__main__':
    main()