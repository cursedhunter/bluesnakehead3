import csv 
import json 

def csv_to_json(csvFilePath, jsonFilePath):
    #read csv file
    with open(csvFilePath, encoding='utf-8') as csvf: 
        #load csv file data using csv library's dictionary reader
        csvReader = csv.DictReader(csvf) 

        edges = []

        #convert each csv row into python dict
        for row in csvReader: 
            #add this python dict to json array
            if row['Node Type'] in ("l3leaf","spine","super-spine"):
                if row['Peer Type'] in ("mlag_peer","l3leaf","spine","super-spine"):
                    node1_dict = {'hostname' : row['Node'],
                                 'interfaceName' : row['Node Interface']}
                    node2_dict = {'hostname' : row['Peer Node'],
                                 'interfaceName' : row['Peer Interface']}
                    edge_entry = {'node1' : node1_dict,
                                 'node2' : node2_dict}
                    edges.append(edge_entry)

        edges_dict = {'edges' : edges}
  
    #convert python jsonArray to JSON String and write to file
    with open(jsonFilePath, 'w', encoding='utf-8') as jsonf: 
        jsonString = json.dumps(edges_dict, indent=4)
        jsonf.write(jsonString)
          
csvFilePath = r'./inventory/documentation/fabric/AMS-topology.csv'
jsonFilePath = r'./inventory/documentation/fabric/AMS-topology.json'
csv_to_json(csvFilePath, jsonFilePath)
