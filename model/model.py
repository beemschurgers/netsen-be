import tensorflow as tf
from tensorflow import keras
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from keras import layers, models, callbacks
from keras.models import load_model
model = load_model("./CNN_model.keras")

import pickle

with open("label_encoder.pkl", "rb") as f:
    labelencoder = pickle.load(f)

# Read the CSV file into a DataFrame
df = pd.read_csv('D:/VSCode_Project/new-model/Merged01.csv')
# df = pd.concat(li, axis=0, ignore_index=True)
# X_test = df[:, :-1]
# Print the DataFrame
print(df[20:21])
data_clean = df.dropna().reset_index()
data_clean.drop_duplicates(keep='first', inplace = True)
data_clean['Label'].value_counts()
print("Read {} rows.".format(len(data_clean)))

data_clean.columns          # This just lists the column names in the data_clean DataFrame—helpful for debugging or inspection.
data_clean = data_clean.dropna().reset_index()    # dropna() removes any rows that contain NaN (missing) values; reset_index() resets the row index after dropping, so it's clean and continuous.
labelencoder = LabelEncoder()    # This creates a LabelEncoder from sklearn, which is used to convert string labels into integers
data_clean['Label'] = labelencoder.fit_transform(data_clean['Label'])    # Encodes the string class labels into integer labels and replaces the original Label column with them.
data_clean['Label'].value_counts()     # Shows how many samples exist for each class (now as numbers). This is useful to check for class imbalance.
print(data_clean.shape)
print(data_clean['Label'].value_counts())

data_np = data_clean.to_numpy(dtype="float32")      # Converts the entire DataFrame into a NumPy array with float32 data type—faster and more efficient for ML model input.
#drop inf values
data_np = data_np[~np.isinf(data_np).any(axis=1)]   # Removes any rows that have infinite values (inf) across any column. This ensures clean numeric data for training


X_test = data_np[:, :-1]
print("data:", X_test.shape)

segment = X_test[20]
print(segment)
test_data = segment.reshape(1, 41, 1).astype('float32')

Y_test = data_np[:, -1]

### How to use labelencoder
pred = model.predict(test_data)
predicted_class = np.argmax(pred)
original_label = labelencoder.inverse_transform([predicted_class])[0]
print("Predicted class label:", original_label)
original_real_label = labelencoder.inverse_transform([np.argmax(Y_test[1233])])[0]
print(original_real_label)