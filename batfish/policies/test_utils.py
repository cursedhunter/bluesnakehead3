from pybfe.datamodel.policy import (
    STATUS_FAIL, STATUS_PASS
)

import os
import csv
import json
from deepdiff import DeepDiff
import pandas as pd 

output_dir = "bf_csv_output"    # output folder

def record_results(bf, status, message):

    session_type = os.environ.get('SESSION_TYPE')

    if session_type == 'bfe':
        if status == STATUS_PASS:
            bf.asserts._record_result(True, status=STATUS_PASS,
                                      message=message)
        elif status == STATUS_FAIL:
            bf.asserts._record_result(False, status=STATUS_FAIL,
                                      message=message)
        else:
            raise Exception

def write_to_csv_output(output_to_save,type):
    # Saving output
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    # Save outputs
    output_to_save.to_csv(f"{output_dir}/{type}.csv")
