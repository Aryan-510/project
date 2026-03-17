import arff
import pandas as pd

with open("Training Dataset.arff") as f:
    data = arff.load(f)

df = pd.DataFrame(data['data'], columns=[x[0] for x in data['attributes']])
df.to_csv("phishing.csv", index=False)

print("CSV created successfully!")
