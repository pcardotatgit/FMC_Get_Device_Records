import json
from crayons import blue, green, white, red, yellow,magenta, cyan

fb = open("device_records.csv","w")  

with open('output_devices_json.json') as json_data:
    json_data_2=json.load(json_data)
    items=json_data_2['items']
    for item in items:
        #print(yellow(items,bold=True))
        lic=""
        for license in item['license_caps']:
            lic+=license+','
        lic='['+lic+']'
        lic=lic.replace(",]","]")
        line_out=item['name']+';'+item['hostName']+';'+lic
        print(yellow(line_out,bold=True))
        fb.write(line_out)	
        fb.write('\n')	
        print("=========================")
print(green("ALL DONE",bold=True))        
fb.close()        