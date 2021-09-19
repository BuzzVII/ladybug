import csv
import json


def main(input_file, offset = 0x400000):
    module_name = input_file.split('.')[0] + '.exe'

    with open(input_file) as fid:
        reader = csv.reader(fid)
        lines = []
        for l in reader:
            lines.append(l)

    labels = {'labels':[]}

    for l in lines[1:]:
        entry = {
          "module": module_name.lower(),
          "address": hex(int(l[1], 16) - offset),
          "manual": True,
          "text": l[0]
        }
        labels['labels'].append(entry)

    output_file = module_name + '.dd32'
    with open(output_file, 'w') as fid:
      json.dump(labels, fid)


if __name__ == "__main__":
    f_name = input("Enter the exported Ghidra CSV:")
    pc_start = input("Enter the address offset:")
    main(f_name)