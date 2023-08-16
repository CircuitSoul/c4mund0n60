from datetime import datetime
import pytz
import subprocess

def currentTimezone():
    # Get the system's time zone using timedatectl
    try:
        time_zone = subprocess.check_output(["timedatectl", "show", "-p", "Timezone", "--value"]).decode().strip()
        return time_zone
    except subprocess.CalledProcessError:
        print("Error getting system time zone")
        time_zone = "UTC"  # Set a default time zone if retrieval fails
        return time_zone
    
def convertToUTC(date):
    # Define the MSK timestamp string
    msk_timestamp_str = date

    # Create a datetime object from the timestamp string
    msk_timestamp = datetime.strptime(msk_timestamp_str, "%Y-%m-%dT%H:%M:%S%Z")

    # Define the MSK time zone
    system_tz = currentTimezone()
    msk_tz = pytz.timezone(system_tz)

    # Localize the datetime object to MSK time zone
    localized_msk_timestamp = msk_tz.localize(msk_timestamp)

    # Convert to UTC time zone
    utc_timestamp = localized_msk_timestamp.astimezone(pytz.utc)

    # Format the UTC timestamp as desired
    formatted_utc_timestamp = utc_timestamp.strftime("%Y-%m-%dT%H:%M:%S%Z")

    # print("Original timestamp:", msk_timestamp)
    # print("Formatted UTC timestamp:", formatted_utc_timestamp)
    
    return formatted_utc_timestamp