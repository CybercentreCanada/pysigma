import os
print(os.listdir())
rules_path = os.path.join('../neo-sigma-master/sigma-master/rules/windows')
for root, _, files in os.walk(rules_path):
    print('root\n',root)
    if root != '.':
        print('files\n',files)
        for file in files:
            print('file')
            print(os.path.join(root,file))
            #os.rmdir(file[:-4])
            #os.mkdir(os.path.join(root,file[:-4]))