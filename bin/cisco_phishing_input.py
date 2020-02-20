# Copyright 2019 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import
import logging
from datetime import datetime
import sys
from cisco_helper import cisco_messages, cisco_client, data_encryption, checkpoint
from splunklib.modularinput import *


class CiscoPhishingInput(Script):
    """All modular inputs should inherit from the abstract base class Script
    from splunklib.modularinput.script.
    They must override the get_scheme and stream_events functions, and,
    if the scheme returned by get_scheme has Scheme.use_external_validation
    set to True, the validate_input function.
    """
    _masked_password = '**********'

    def get_scheme(self):
        """When Splunk starts, it looks for all the modular inputs defined by
        its configuration, and tries to run them with the argument --scheme.
        Splunkd expects the modular inputs to print a description of the
        input in XML on stdout. The modular input framework takes care of all
        the details of formatting XML and printing it. The user need only
        override get_scheme and return a new Scheme object.

        :return: scheme, a Scheme object
        """

        scheme = Scheme("Cisco Advanced Phishing Protection")

        scheme.description = 'Streams events from Cisco Advanced Phishing Protection "APP" appliance logs'
        # If you set external validation to True, without overriding validate_input,
        # the script will accept anything as valid. Generally you only need external
        # validation if there are relationships you must maintain among the
        # parameters, such as requiring min to be less than max in this example,
        # or you need to check that some resource is reachable or valid.
        # Otherwise, Splunk lets you specify a validation string for each argument
        # and will run validation internally using that string.
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        message_limit_arg = Argument("message_limit")
        message_limit_arg.title = "Messages Per Page"
        message_limit_arg.data_type = Argument.data_type_number
        message_limit_arg.description = "Number of messages per page."
        message_limit_arg.required_on_create = True

        scheme.add_argument(message_limit_arg)

        start_date_arg = Argument(
            name='initial_start_date',
            title='Initial Start Date',
            description='The starting point of fetching initial data',
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        )
        scheme.add_argument(start_date_arg)

        client_id_arg = Argument(
            name='client_id',
            title='Client Id',
            description='Client id for cisco API',
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        )
        scheme.add_argument(client_id_arg)

        secret_arg = Argument(
            name='client_secret',
            title='Client Secret',
            description='Client secret for cisco API',
            data_type=Argument.data_type_string,
            required_on_create=True,
            required_on_edit=True
        )
        scheme.add_argument(secret_arg)

        duration_arg = Argument(
            name='duration',
            title='Duration',
            description='How long each execution will run in minutes.',
            data_type=Argument.data_type_number,
            required_on_create=True,
            required_on_edit=True
        )
        scheme.add_argument(duration_arg)

        token_host_arg = Argument(
            name='cisco_token_host',
            title='Cisco Token Host'
        )
        scheme.add_argument(token_host_arg)

        service_host_arg = Argument(
            name='cisco_service_host',
            title='Cisco Service Host'
        )
        scheme.add_argument(service_host_arg)

        return scheme

    def validate_input(self, validation_definition):
        """
        When using external validation, after splunkd calls the modular input with
        --scheme to get a scheme, it calls it again with --validate-arguments for
        each instance of the modular input in its configuration files, feeding XML
        on stdin to the modular input to do validation. It is called the same way
        whenever a modular input's configuration is edited.

        :param validation_definition: a ValidationDefinition object
        """
        # Get the values of the parameters
        try:
            message_limit = int(validation_definition.parameters["message_limit"])
        except:
            raise ValueError("Please enter value between 1 to 1000.")

        if message_limit > 1000:
            raise ValueError("The maximum message limit value is 1000.")
        if message_limit <= 0:
            raise ValueError("The message limit has to be greater than 0.")

        # Get the values of the parameters
        try:
            duration = int(validation_definition.parameters["duration"])
        except:
            raise ValueError("Please enter value between 1 to 60.")

        if duration > 60:
            raise ValueError("The maximum duration value is 60.")
        if duration <= 0:
            raise ValueError("The duration value has to be greater than 0.")
        try:
            initial_start_date = datetime.strptime(validation_definition.parameters["initial_start_date"],
                                                   '%Y-%m-%dT%H:%M:%S+00:00')
        except:
            raise ValueError(
                "Invalid initial start date value, please use the following format 'yyyy-mm-ddThh:mm:ss+00:00'")

    def stream_events(self, inputs, ew):
        """This function handles all the action: splunk calls this modular input
        without arguments, streams XML describing the inputs to stdin, and waits
        for XML on stdout describing events.

        If you set use_single_instance to True on the scheme in get_scheme, it
        will pass all the instances of this input to a single instance of this
        script.

        :param inputs: an InputDefinition object
        :param ew: an EventWriter object
        """

        checkpoint_dir = inputs.metadata["checkpoint_dir"]
        session_key = inputs.metadata["session_key"]

        try:
            # Go through each input for this modular input
            for input_name, input_item in inputs.inputs.iteritems():
                # Get fields from the InputDefinition object
                client_id = input_item['client_id']
                masked_secret = input_item['client_secret']
                initial_start_date = datetime.strptime(input_item["initial_start_date"],
                                                       '%Y-%m-%dT%H:%M:%S+00:00')

                config_provider = data_encryption.DataEncryption(session_key, input_name)
                # get the real secret from splunk client
                configs = {
                    'client_id': input_item['client_id'],
                    'client_secret': self._masked_password,
                    'duration': input_item['duration'],
                    'message_limit': input_item['message_limit'],
                    'initial_start_date': input_item['initial_start_date'],
                    'cisco_token_host': input_item['cisco_token_host'],
                    'cisco_service_host': input_item['cisco_service_host']
                }
                secret = config_provider.encrypt_and_get_password(client_id, masked_secret, ew,
                                                                  configs)

                check_point = checkpoint.CheckPoint(checkpoint_dir, input_name)
                initial_time = check_point.get_checkpoint_value('last_processed_time') or (
                    initial_start_date)

                ew.log('INFO', 'Cisco phishing data input checkpoint time: ' + str(initial_time))

                # set secret back for cisco client to get token
                configs['client_secret'] = secret
                cisco_client_instance = cisco_client.CiscoClient(configs)

                messages = cisco_client_instance.get_messages(initial_time)

                cisco_message_processor = cisco_messages.CiscoMessageProcessor(check_point)
                cisco_message_processor.save_messages(messages, input_name, ew)
        except Exception as e:
            ew.log("ERROR", "Cisco Messages Processor Error: %s" % logging.exception(e))


if __name__ == "__main__":
    sys.exit(CiscoPhishingInput().run(sys.argv))
