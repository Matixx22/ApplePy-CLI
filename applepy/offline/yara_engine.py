import yara

class YaraEngine():
    
    def detect(rules: dict, file):
        
        rules = yara.compile(filepaths=rules)


        with open(file, 'rb') as file:
            file_content = file.read()

            matches = rules.match(data=file_content)
            # print(matches.rule)

            for match in matches:
                print(match.rule, match.meta, match.strings)