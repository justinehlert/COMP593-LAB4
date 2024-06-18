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
import pandas as pd
import os

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

    #Empty Dict to hold outputs
    portsDict = {}

    regex = r'DPT=(\d{1,5})'
    filteredRecords, capturedData = la.filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False)

    #Iterating through filteredRecords to find ports.
    for record in filteredRecords:
        #get a list of matching regex in records
        addr = re.findall(regex, record)
        for ip in addr:
            if ip in portsDict:
                #if a port already exists in the dict, add one to the count value
                portsDict[ip]+=1
            else:
                #else start a new count at 1
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
    destPort = f'DPT=({port_number})'
    captureColumns = r'(\b[A-Za-z]{3} \d{1,2}\b) (\d{2}:\d{2}:\d{2}).*SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*SPT=(\d{1,5}).*' + destPort
    filteredRecords, extractedData = la.filter_log_by_regex(log_path, captureColumns, ignore_case=True, print_summary=False, print_records=False)
    # Generate the CSV report
    extract_df = pd.DataFrame(extractedData, columns=('DATE', 'TIME', 'SRC IP', 'DST IP', 'SRC PORT', 'DST PORT'))

    #Creating a folder to hold the report outputs if it does not already exist
    dirName = makeDirectoryIfNotPresent('.\\Output_Reports')
    #Return path of orders directory
    extract_df.to_csv(f'.\\{dirName}\\destination_port_{port_number}_report.csv', index=False)
    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    # TODO: Complete function body per step 10
    captureColumns = r'(\b[A-Za-z]{3} \d{1,2}\b) (\d{2}:\d{2}:\d{2}).*Invalid user (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    # Get data from records that show attempted invalid user login
    filteredRecords, extractedData = la.filter_log_by_regex(log_path, captureColumns, ignore_case=True, print_summary=False, print_records=False)
    # Generate the CSV report
    extract_df = pd.DataFrame(extractedData, columns=('DATE', 'TIME', 'USERNAME', 'IP Address'))
    dirName = makeDirectoryIfNotPresent('.\\Output_Reports')
    #Return path of orders directory
    extract_df.to_csv(f'.\\{dirName}\\invalid_users.csv', index=False)
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    # TODO: Complete function body per step 11
    ipMatch = f'{ip_address}'
    # Get all records that have the specified sourec IP address
    filteredRecords, extractedData = la.filter_log_by_regex(log_path, ipMatch, ignore_case=True, print_summary=False, print_records=False)
    # Save all records to a plain text .log file
    
    dirName = makeDirectoryIfNotPresent('.\\Output_Reports')
    logFile = open(f'{dirName}\\source_ip_{re.sub(r'\.', '_', ip_address)}.log', 'w')
    for line in filteredRecords:
        logFile.write(f'{line}\n')
    logFile.close()
    return

def makeDirectoryIfNotPresent(directoryName):
    """Creates a new directory if it's not present
    
    Args: 
        Path of the desired directory. Relative to the script or absolute
    """
    try:
        os.mkdir(f'{directoryName}')
    except OSError:
        pass    
    return directoryName

if __name__ == '__main__':
    main()