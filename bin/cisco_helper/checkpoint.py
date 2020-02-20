from datetime import datetime
import json
import os


class CheckPoint(object):
    def __init__(self, checkpoint_dir, input_name):
        self._checkpoint_dir = checkpoint_dir
        self._input_name = input_name

    def checkpoint_filename(self):
        input_stanza_parts = self._input_name.split("//")
        input_name = input_stanza_parts[1]

        # this assumes input_name will always be an acceptable filename for simplicity
        # if that is not the case input_name needs to be sanitized somehow
        return os.path.join(self._checkpoint_dir, input_name)

    def update_checkpoint(self, last_processed_time):
        state = {'last_processed_time': last_processed_time}
        checkpoint_filename = self.checkpoint_filename()

        with open(checkpoint_filename, "w") as checkpoint_file:
            json.dump(state, checkpoint_file)

    def get_checkpoint(self):

        checkpoint_filename = self.checkpoint_filename()

        if os.path.exists(checkpoint_filename):
            with open(checkpoint_filename, "r") as checkpoint_file:
                return json.load(checkpoint_file)

    def get_checkpoint_value(self, key):

        checkpoint_contents = self.get_checkpoint()
        if checkpoint_contents and checkpoint_contents is not None and checkpoint_contents[key] is not None:
            return datetime.strptime(checkpoint_contents[key], '%Y-%m-%dT%H:%M:%S+00:00')
