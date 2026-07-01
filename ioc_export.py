import csv
import json


def export_iocs_csv(iocs):

    with open("iocs.csv", "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow(["Type", "Indicator"])

        for ioc in iocs:
            writer.writerow([ioc["type"], ioc["value"]])


def export_iocs_json(iocs):

    with open("iocs.json", "w", encoding="utf-8") as file:

        json.dump(iocs, file, indent=4)
