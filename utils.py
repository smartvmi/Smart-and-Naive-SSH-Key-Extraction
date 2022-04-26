"""
File that contains all commonly used functions
"""
import numpy as np
import os
import json
from datetime import datetime
global file_names
global fptr
from timeit import default_timer as timer

ROOT = "../Smart-VMI/data/new"
VALIDATION_PATH = "../Smart-VMI/data/validation"
MODEL_PATH = "./models"
LOG_PATH = "./logs"
RESULTS_PATH = "./results"
TYPES = ["client-side", "dropbear", "OpenSSH", "port-forwarding", "scp", "normal-shell"]
LENGTHS = [16, 24, 32, 64]


class WrappedClassifier:
    def __init__(self, resampled_classifier, classifier, final_stage_classifier):
        self.resampled_classifier = resampled_classifier
        self.classifier = classifier
        self.final_stage = final_stage_classifier

    def predict(self, x):
        test_rc = self.resampled_classifier.predict_proba(x)
        test_clf = self.classifier.predict_proba(x)

        transformed_input = np.hstack((test_rc, test_clf))
        results = self.final_stage.predict(transformed_input)
        return results

    def return_classifiers(self):
        return self.classifier, self.resampled_classifier, self.final_stage


def init():
    global file_names
    global fptr
    file_names = []
    fptr = None


def close():
    global fptr
    if fptr is not None:
        fptr.close()
        fptr = None


def print_(print_str):
    global fptr
    if fptr is None:
        # Create the directory if it is not present
        if os.path.exists(LOG_PATH) is False:
            os.makedirs(LOG_PATH)
        path = os.path.join(LOG_PATH, "Output_" + str(datetime.now()) + ".txt")
        fptr = open(path, "w")

    fptr.write(str(datetime.now()) + ":\t" + print_str + "\n")
    print(str(datetime.now()) + ":\t" + print_str)


def read_keys(path):
    with open(path, "r") as fp:
        data = fp.readlines()

    # Extract upto 6 keys
    keys = []
    temp_key = bytearray()
    for row in data:
        # Empty row
        if len(row.strip()) == 0:
            continue
        curr_row = row.strip()
        if 'KEY' in curr_row:
            # key start
            if len(temp_key) > 0:
                keys.append(temp_key)
            temp_key = bytearray()
        else:
            curr_row = curr_row[23:].strip()
            temp_key = temp_key + bytearray.fromhex(curr_row)

    if len(temp_key) > 0:
        keys.append(temp_key)
    return keys


def create_dataset(folder_path, keys_path):
    """
    The aim is to split the raw file into multiple blocks of 128 bytes
    If the key for the file is present in the block then that page will be labelled True else False
    This will be an unbalanced dataset
    :param folder_path: path of the heap dump files
    :param keys_path: path to the folder containing the corresponding keys of dumps
    :return:
    """

    global file_names

    window_size = 128
    key_size = 64

    files = os.listdir(folder_path)
    dataset = []
    labels = []
    offsets = []
    lengths = []
    for idx, file in enumerate(files):

        if file in file_names:
            print('ERROR: VALIDATION FILE OVERLAPS WITH TRAINING DATASET. \n %s' % file)
            continue

        file_names.append(file)

        path = os.path.join(folder_path, file)
        key_path = os.path.join(keys_path, file[:-9] + '-key.log')
        curr_keys = read_keys(key_path)
        with open(path, "rb") as fp:
            data = fp.read()
            data = bytearray(data)
            idx = 0
            # We create 16 byte blocks
            while idx + window_size <= len(data):
                window_sum = sum(data[idx:idx+window_size])
                if window_sum == 0:
                    idx += key_size
                    continue
                dataset.append(data[idx:idx+window_size])

                found = [l_idx if curr_keys[l_idx] in data[idx:idx+window_size]
                         else 0 for l_idx in range(len(curr_keys))]
                if any(found) is True:
                    labels.append(1)
                    offset = [data[idx:idx + window_size].find(curr_keys[element]) for element in found if element != 0]
                    curr_lengths = [len(curr_keys[element]) for element in found if element != 0]
                    if len(offset) > 1:
                        print("Multiple keys detected in same window")
                    else:
                        offsets.append(offset[0])
                        lengths.append(curr_lengths[0])
                else:
                    labels.append(0)
                    offsets.append(0)
                    lengths.append(0)

                if len(labels) != len(offsets):
                    print("Hello")
                idx += key_size

        window_sum = sum(data[-window_size:])
        if idx < len(data) and window_sum > 0:

            dataset.append(data[-window_size:])
            found = [l_idx if curr_keys[l_idx] in data[idx:idx + window_size]
                     else 0 for l_idx in range(len(curr_keys))]

            if any(found) is True:
                labels.append(1)
                offset = [data[idx:idx + window_size].find(curr_keys[element]) for element in found if element != 0]
                offsets.append(offset[0])

                curr_lengths = [len(curr_keys[element]) for element in found if element != 0]
                lengths.append(curr_lengths[0])

                assert(len(offsets) == 1)

            else:
                labels.append(0)
                offsets.append(0)
                lengths.append(0)

    return dataset, labels, offsets, lengths


def read_files(paths, key_paths, model=None, window_size=128, key_size=64, root_dir=None, oversample=False):
    """
    Reads a list of files and their corresponding keys
    :param paths: File paths as a list
    :param key_paths: Path of corresponding key files
    :param model: Doc2Vec model for concatenating the model to the block
    :param window_size: Size of the block which the binary file is to sliced
    :param key_size: Length of the largest key in bytes
    :param root_dir: Root of the directory if it is not the default ROOT
    :param oversample: Increase the number of positive samples by shifting the key by 8 bytes
    :return: Matrix of bytes of shape Nx128, labels, offsets
    """
    dataset = []
    labels = []
    offsets = []

    if root_dir is None:
        base_path_length = len(ROOT) + 1
    else:
        base_path_length = len(root_dir) + 1

    for path, key_path in zip(paths, key_paths):

        assert (key_path[:-5] in path)
        curr_keys = read_key_files(key_path)
        with open(path, "rb") as fp:
            data = fp.read()
            data = bytearray(data)
            idx = 0

            # Get the heap representation by Doc2Vec
            feature_vector = []
            if model is not None:
                feature_vector = model.infer_vector(list(map(str, data)))
                feature_vector = feature_vector.tolist()

            for curr_key in curr_keys:
                if curr_key not in data:
                    print(str(curr_key) + " not found in data file:" + path)

            enc_alg_info = path[base_path_length:].split(sep="/")[:-1]
            assert (enc_alg_info[0] in TYPES)
            assert (int(enc_alg_info[2]) in LENGTHS)

            # We create 16 byte blocks
            while idx + window_size <= len(data):
                window_sum = sum(data[idx:idx + window_size])
                if window_sum == 0:
                    idx += key_size
                    continue

                if model is None:
                    dataset.append(data[idx:idx + window_size])
                else:
                    temp = list(map(float, data[idx:idx + window_size])) + feature_vector
                    dataset.append(temp)

                found = [l_idx for l_idx in range(len(curr_keys)) if curr_keys[l_idx] in data[idx:idx + window_size]]
                if len(found) > 0:
                    labels.append(1)
                    offset = [data[idx:idx + window_size].find(curr_keys[element]) for element in found]
                    if len(offset) > 1:
                        offsets.append(2)  # Setting it as 2 so that we know that there are multiple keys in there
                    else:
                        offsets.append(offset[0])
                else:
                    labels.append(0)
                    offsets.append(0)

                if len(labels) != len(offsets):
                    print("Hello")
                idx += key_size

        window_sum = sum(data[-window_size:])
        if idx < len(data) and window_sum > 0:

            if model is None:
                dataset.append(data[-window_size:])
            else:
                temp = list(map(float, data[-window_size:])) + feature_vector
                dataset.append(temp)

            found = [l_idx if curr_keys[l_idx] in data[idx:idx + window_size]
                     else 0 for l_idx in range(len(curr_keys))]

            if any(found) is True:
                labels.append(1)
                offset = [data[idx:idx + window_size].find(curr_keys[element]) for element in found if element != 0]
                offsets.append(offset[0])

                assert (len(offsets) == 1)

            else:
                labels.append(0)
                offsets.append(0)

    return dataset, labels, offsets


def read_key_files(path):
    """
    Reads the present keys with a JSON key file
    :param path: path of the key file
    :return: keys in a list
    """
    key_names = ['KEY_A', 'KEY_B', 'KEY_C', 'KEY_D', 'KEY_E', 'KEY_F']
    keys = []
    with open(path, "r") as fp:
        data = json.loads(fp.read())

    for key in key_names:

        key_value = data.get(key, None)

        # If the key is not found or key is empty
        if key_value is None or len(key_value) == 0:
            continue

        keys.append(bytearray.fromhex(key_value))

    return keys


def get_dataset_file_paths(path, deploy=False):
    import glob
    paths = []

    file_paths = []
    key_paths = []

    sub_dir = os.walk(path)
    for directory in sub_dir:
        paths.append(directory[0])

    paths = set(paths)
    for path in paths:
        # print(os.listdir(path))
        files = glob.glob(os.path.join(path, '*.raw'), recursive=False)

        if len(files) == 0:
            continue

        for file in files:
            key_file = file[:-9] + ".json"
            if os.path.exists(key_file) and deploy is False:
                file_paths.append(file)
                key_paths.append(key_file)

            elif deploy is True:
                file_paths.append(file)

            else:
                print_("Corresponding Key file does not exist for :%s" % file)

    return file_paths, key_paths


def get_metrics(y_true, y_pred, return_cm=False):
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    acc = accuracy_score(y_true=y_true, y_pred=y_pred)
    pr = precision_score(y_true=y_true, y_pred=y_pred)
    recall = recall_score(y_true=y_true, y_pred=y_pred)
    f1 = f1_score(y_true=y_true, y_pred=y_pred)
    cm = confusion_matrix(y_true=y_true, y_pred=y_pred)
    tp = cm[1][1]
    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]

    if return_cm is False:
        return acc, pr, recall, f1, tp, tn, fp, fn
    else:
        return acc, pr, recall, f1, cm


def test(clf, file_paths, key_paths, window_size=128, model=None, root_dir=None):
    """

    :param clf: model to be tested
    :param file_paths:
    :param key_paths:
    :param window_size: Size of the block of data to be extracted from heap at a time
    :param model: Doc2Vec model for generating representations of the heap
    :return: truth, predicted values and data frame with metrics on each group of test
    """
    import pandas as pd

    idx = 0
    y_true = []
    y_pred = []

    if root_dir is None:
        base_path_length = len(ROOT) + 1
    else:
        base_path_length = len(root_dir) + 1

    df = pd.DataFrame(columns=['Algorithm', 'Version', 'Key Length', 'Total Instances', 'Positive Instances',
                               'Negative Instances', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'True Negatives',
                               'True Positives', 'False Positives', 'False Negatives'])

    while idx < len(key_paths):

        enc_alg_info = file_paths[idx][base_path_length:].split(sep="/")[:-1]

        assert (enc_alg_info[0] in TYPES)
        assert (int(enc_alg_info[2]) in LENGTHS)

        path_idx = file_paths[idx].rfind("/")
        limit = 1
        while idx + limit < len(key_paths) and file_paths[idx][:path_idx] in file_paths[idx + limit]:
            limit += 1

        # print((enc_alg_info[0], enc_alg_info[1], enc_alg_info[2], idx, limit, len(key_paths)))

        x_test, curr_labels, _ = read_files(paths=file_paths[idx:idx + limit], key_paths=key_paths[idx:idx + limit],
                                            model=model, window_size=window_size, root_dir=root_dir)

        x_test = np.array(x_test).astype(int)
        curr_pred = clf.predict(x_test)

        y_true = y_true + curr_labels
        y_pred = y_pred + curr_pred.tolist()

        acc, pr, recall, f1, tp, tn, fp, fn = get_metrics(y_true=curr_labels, y_pred=curr_pred)

        total = tp + tn + fp + fn
        total_neg = tn + fp
        total_pos = tp + fn

        df.loc[len(df.index)] = enc_alg_info[0], enc_alg_info[1], enc_alg_info[2], total, total_pos, total_neg, acc, \
                                pr, recall, f1, tn, tp, fp, fn

        idx += limit

    return y_true, y_pred, df


def print_metrics(y_test, y_pred):
    acc, pr, recall, f1, cm = get_metrics(y_true=y_test, y_pred=y_pred, return_cm=True)
    print_("Accuracy: %f" % acc)
    print_("Precision: %f" % pr)
    print_("Recall: %f" % recall)
    print_("F1-Measure: %f" % f1)
    print_("\nConfusion Matrix:\n" + str(cm))


def get_splits(path, val_per=0.15, test_per=0.15, random_state=42):
    from sklearn.model_selection import train_test_split
    import time

    start = timer()
    file_paths, key_paths = get_dataset_file_paths(path)
    end = timer()
    print_('Time taken for finding all files: %f' % (end - start))

    start = timer()
    train_files, val_files, train_keys, val_keys, = \
        train_test_split(file_paths, key_paths, test_size=test_per, random_state=random_state)
    end = timer()
    print_('Time taken for splitting: %f' % (end - start))

    start = timer()
    train_files, test_files, train_keys, test_keys, = \
        train_test_split(train_files, train_keys, test_size=val_per, random_state=random_state)
    end = timer()
    print_('Time taken for secondary splitting: %f' % (end - start))

    return train_files, train_keys, test_files, test_keys, val_files, val_keys


def train_classifier(dataset, labels, test_paths=[], test_keys=[], retrain_rf=False, retrain_resampled=False,
                     retrain_final=False):
    """

    :param dataset: Paths of files to be trained
    :param labels:  The corresponding keys
    :param test_paths: Paths of heaps to be tested
    :param test_keys: Paths of corresponding key files
    :param retrain_rf: Whether to retrain the random forest or load it from disk
    :param retrain_resampled: Whether to retrain the resampled data classifier or load it from disk
    :param retrain_final: Whether to retrain the final classifier or not
    :return: Wrapped classifier
    """

    import time
    import pickle

    from imblearn.over_sampling import SMOTE
    from sklearn.ensemble import RandomForestClassifier

    path = os.path.join(MODEL_PATH, 'rf.pkl')
    if retrain_rf is True or not os.path.exists(path):
        start = time.time()
        rf = RandomForestClassifier(n_estimators=5)
        rf.fit(X=dataset, y=labels)
        end = time.time()
        print_('Time taken for training the classifier: %f' % (end - start))

        with open(path, 'wb') as fp:
            pickle.dump(rf, fp)

    else:
        with open(path, 'rb') as fp:
            rf = pickle.load(fp)

    path = os.path.join(MODEL_PATH, 'resampled_clf.pkl')
    if retrain_resampled is True or not os.path.exists(path):
        # Use SMOTE oversampling
        start = time.time()
        sm = SMOTE()
        x_train, y_train = sm.fit_resample(dataset, labels)
        end = time.time()
        print_('Time taken for resampling: %f' % (end - start))

        #  clf.partial_fit(X=np.array(dataset).astype(int), y=labels, classes=classes)
        start = time.time()
        resampled_clf = RandomForestClassifier(n_estimators=5)
        resampled_clf.fit(X=np.array(x_train), y=y_train)
        end = time.time()
        print_('Time taken for training the classifier on resampled data: %f' % (end - start))

        # Clear memory of x_train and y_train
        x_train = None
        y_train = None

        with open(path, 'wb') as fp:
            pickle.dump(resampled_clf, fp)

    else:
        with open(path, 'rb') as fp:
            resampled_clf = pickle.load(fp)

    path = os.path.join(MODEL_PATH, 'secondary_clf.pkl')
    if retrain_final is True or not os.path.exists(path=path):

        # Predict probabilities to generate modified training vectors
        start = time.time()
        resampled_predicted = resampled_clf.predict_proba(dataset)
        end = time.time()
        print_('Time taken for predicting on the resampled classifier: %f' % (end - start))

        start = time.time()
        non_resampled_predicted = rf.predict_proba(dataset)
        end = time.time()
        print_('Time taken for predicting on the random forest classifier: %f' % (end - start))

        # Stack the probabilities together
        combined_dataset = np.hstack((resampled_predicted, non_resampled_predicted))

        # Train Random Forest classifier on the modified input data
        start = time.time()
        final_clf = RandomForestClassifier(n_estimators=3)
        final_clf.fit(X=np.array(combined_dataset), y=labels)
        end = time.time()
        print_('Time taken for training the final classifier: %f' % (end - start))

        # Save the model to the disk
        path = os.path.join(MODEL_PATH, 'secondary_clf.pkl')
        with open(path, 'wb') as fp:
            pickle.dump(final_clf, fp)

    else:
        with open(path, 'rb') as fp:
            final_clf = pickle.load(fp)

    clf = WrappedClassifier(resampled_classifier=resampled_clf, classifier=rf, final_stage_classifier=final_clf)

    if len(test_paths) == 0:
        return clf

    print('Testing Dataset')
    start = time.time()
    y_test, y_pred, df = test(clf=clf, file_paths=test_paths, key_paths=test_keys)
    end = time.time()
    print_('Time taken for reading and testing: %f' % (end - start))

    path = os.path.join(RESULTS_PATH, "Test_Results_" + str(datetime.now()) + ".csv")
    df.to_csv(path)

    start = time.time()
    print_('METRICS OF TEST SET')
    print_metrics(y_test=y_test, y_pred=y_pred)
    end = time.time()
    print_('Time taken for computing metrics: %f' % (end - start))

    return clf


def load_models(load_high_recall_only=False):
    import time
    import pickle
    start = timer()
    path = os.path.join(MODEL_PATH, 'resampled_clf_entropy.pkl')
    with open(path, 'rb') as fp:
        resampled_clf = pickle.load(fp)
    end = timer()
    print_('Time taken for loading high recall classifier: %f' % (end - start))

    if load_high_recall_only is True:
        return resampled_clf
    
    start = timer()
    path = os.path.join(MODEL_PATH, 'rf_entropy.pkl')
    with open(path, 'rb') as fp:
        rf = pickle.load(fp)
    end = timer()
    print_('Time taken for loading high precision classifier: %f' % (end - start))

    start = timer()
    path = os.path.join(MODEL_PATH, 'secondary_clf_entropy.pkl')
    with open(path, 'rb') as fp:
        final_clf = pickle.load(fp)
    end = timer()
    print_('Time taken for loading secondary classifier: %f' % (end - start))

    clf = WrappedClassifier(resampled_classifier=resampled_clf, classifier=rf, final_stage_classifier=final_clf)
    return clf

