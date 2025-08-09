__artifacts_v2__ = {
    "Android Notification History": {
        "name": "Android Notification History",
        "description": "Get Android notifications' history, policy and settings. This parser is based on a research project",
        "author": "Evangelos Dragonas (@theAtropos4n6)",
        "version": "0.0.1",
        "date": "2024-07-02",
        "requirements": "",
        "category": "Android Notification History",
        "paths": (
            '**/system_ce/*/notification_history/history/*',
            '**/system/users/*/settings_secure.xml',
            '**/system/notification_policy.xml',
        ),
        "function": "get_notificationHistory"
    }
}


import xml.etree.ElementTree as ET
from datetime import *
import os
import scripts.artifacts.notification_history_pb.notificationhistory_pb2 as notificationhistory_pb2

from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, abxread, checkabx,convert_ts_int_to_utc,convert_utc_human_to_timezone


def get_notificationHistory(files_found, report_folder, seeker, wrap_text):
    data_pb_list = []
    for file_found in files_found:
        file_found = str(file_found)
        file_name = os.path.basename(file_found)
        #parsing settings_secure.xml
        if file_name.endswith('settings_secure.xml'):
            data_list = []
            user = os.path.basename(os.path.dirname(file_found))
            if (checkabx(file_found)):
                multi_root = True
                tree = abxread(file_found, multi_root)
            else:
                tree = ET.parse(file_found)
            
            root = tree.getroot()
            for setting in root.findall(".//setting"):
                if setting.attrib.get('name') == 'notification_history_enabled':
                    value = setting.attrib.get('value')
                    value = "Enabled" if value == "1" else "Disabled" if value == "0" else "Unknown"
                    data_list.append((value, user))
                else:
                    pass # setting not available

            if data_list:
                description = f'Indicates whether "Notification History" feature is enabled.'
                report = ArtifactHtmlReport('Android Notification History - Status')
                report.start_artifact_report(report_folder, 'Status',description)
                report.add_script()
                data_headers = ('Status', 'User')
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()
                
                tsvname = f'Android Notification History - Status'
                tsv(report_folder, data_headers, data_list, tsvname)
                
            else:
                logfunc('No Android Notification History - Status data available')
        
        #parsing notification_policy.xml
        if file_name.endswith('notification_policy.xml'):
            data_list = []
            if (checkabx(file_found)):
                multi_root = False
                tree = abxread(file_found, multi_root)
            else:
                tree = ET.parse(file_found)
            
            root = tree.getroot()
            for elem in root:
                if elem.tag == 'snoozed-notifications':
                    if list(elem):
                        for notification in elem:
                            if notification.tag == 'notification':
                                notification_ts = int(notification.attrib.get('time'))
                                snooze_time = convert_utc_human_to_timezone(convert_ts_int_to_utc(int(notification_ts/1000.0)),'UTC')
                                notification_key = notification.attrib.get('key')
                                data_list.append((f'{snooze_time}', notification_key))
                    else:
                        pass #no snoozed notifications found    
            if data_list:
                description = f'Notifications the user chose to snooze for a specific time interval'
                report = ArtifactHtmlReport('Android Notification History - Snoozed notifications')
                report.start_artifact_report(report_folder, 'Snoozed notifications', description) #'Android Notification History - Snoozed notifications')
                report.add_script()
                data_headers = ('Reminder Time', 'Snoozed Notification')
                report.write_artifact_data_table(data_headers, data_list, file_found)
                report.end_artifact_report()
                
                tsvname = f'Android Notification History - Snoozed notifications'
                tsv(report_folder, data_headers, data_list, tsvname)
                
            else:
                logfunc('No Android Notification History - Snoozed notifications data available')

        else:
            #iterate through the notification pbs
            try:
                notification_history = notificationhistory_pb2.NotificationHistoryProto()
                with open(file_found, 'rb') as f:
                    try:
                        notification_history.ParseFromString(f.read()) #The error 'Wrong wire type in tag. ' likely happens due to the given .proto map file.  
                    except Exception as e:
                        logfunc(f'Error in the ParseFromString() function. The error message was: {e}')

                    package_map = {i + 1: pkg for i, pkg in enumerate(notification_history.string_pool.strings)} # one of the protobuf files stores the package name and indexes

                    major_version = notification_history.major_version if notification_history.HasField('major_version') else None # notification format version should be 1
                    for notification in notification_history.notification:
                        package_name = notification.package if notification.package else package_map.get(notification.package_index, "") #retrieves package from the map if not stored locally
                        
                        #this block tries to fetch the value of each field from within the parsed protobuf file e.g. variable user_id -> recovers the user_id field from the pb
                        fields = ['uid', 'user_id', 'package_index', 'channel_name', 'channel_id','channel_id_index', 'channel_name_index', 'conversation_id', 'conversation_id_index']
                        defaults = {field: 'Error' for field in fields}
                        values = {}
                        for field in fields:
                            try:
                                values[field] = getattr(notification, field)
                            except AttributeError:
                                values[field] = 'Error'
                        #extra block that does the same for the notifications with icons
                        if notification.HasField('icon'):
                            icon_fields = ['image_type', 'image_bitmap_filename', 'image_resource_id', 'image_resource_id_package','image_data_length', 'image_data_offset', 'image_uri']
                            for icon_field in icon_fields:
                                values[icon_field] = getattr(notification.icon, icon_field)
                        else:
                            icon_fields = [
                                'image_type', 'image_bitmap_filename', 'image_resource_id', 'image_resource_id_package',
                                'image_data_length', 'image_data_offset', 'image_uri'
                            ]
                            for icon_field in icon_fields:
                                values[icon_field] = None
                        #here the returned values are assigned to the variables which are reported
                        uid = values['uid']
                        user_id = values['user_id']
                        package_index = values['package_index']
                        channel_name = values['channel_name']
                        channel_id = values['channel_id']
                        channel_id_index = values['channel_id_index']
                        channel_name_index = values['channel_name_index']
                        conversation_id = values['conversation_id']
                        conversation_id_index = values['conversation_id_index']
                        posted_time = convert_utc_human_to_timezone(convert_ts_int_to_utc(int(notification.posted_time_ms/1000.0)),'UTC') if notification.HasField('posted_time_ms') else None
                        title = notification.title if notification.HasField('title') else None
                        text = notification.text if notification.HasField('text') else None
                        image_type = values['image_type']
                        image_bitmap_filename = values['image_bitmap_filename']
                        image_resource_id = values['image_resource_id']
                        image_resource_id_package = values['image_resource_id_package']
                        image_data_length = values['image_data_length']
                        image_data_offset = values['image_data_offset']
                        image_uri = values['image_uri']
                        file_creation = convert_utc_human_to_timezone(convert_ts_int_to_utc(int(file_name)/1000.0),'UTC')
                        data_pb_list.append((f'{posted_time}',title,text,package_name,user_id,uid,package_index,channel_name,channel_name_index,channel_id,channel_id_index,conversation_id,conversation_id_index,major_version,image_type,image_bitmap_filename,image_resource_id,image_resource_id_package,image_data_length,image_data_offset,image_uri,file_name,f'{file_creation}'))
            except Exception as e:
                logfunc(f'Error while opening notification pb files. The error message was:" {e}"')

    if len(data_pb_list) > 0:
        description = f'A history of the notifications that landed on the device during the last 24h'
        report = ArtifactHtmlReport('Android Notification History - Notifications')
        report.start_artifact_report(report_folder, f'Notifications', description)
        report.add_script()
        data_headers = ('Posted Time','Title', 'Text','Package Name','User ID','UID','Package Index','Channel Name','Channel Name Index','Channel ID','Channel ID Index','Conversation ID','Conversation ID Index','Major Version','Image Type','Image Bitmap Filename','Image Resource ID','Image Resource ID Package','Image Data Length','Image Data Offset','Image URI','Protobuf File Name','Protobuf File Creation Date')#,'','','','','','','','','','','','','','')
        file_directory = os.path.dirname(file_found)  
        report.write_artifact_data_table(data_headers, data_pb_list, file_directory, html_escape=False)
        report.end_artifact_report()
        
        tsvname = f'Android Notification History - Notifications'
        tsv(report_folder, data_headers, data_pb_list, tsvname)
        
        tlactivity = f'Android Notification History - Notifications'
        timeline(report_folder, tlactivity, data_pb_list, data_headers)
    else:
        logfunc(f'No Android Notification History - Notifications available')