=========================
Troubleshooting Autograph
=========================

.. sectnum::
.. contents:: Table of Contents

These procedures assume that:

- Production has been deployed successfully
- Production has passed all post deployment QA checks


Reported Issue
========================

Report of 401 error
-------------------

Collect the following information from reporter:

- Autograph `key_id` (if different from Hawk `key_id`)
- Hawk `key_id`
- Has this `key_id` ever worked before?
- Time range error occurred.
- Client location (Taskcluster or not)

Process:

#. Confirm 401 shows in `autograph logs`_. If no such entries, problem exists
   outside of Autograph.

#. `Verify credentials work`_ for the specific `key_id`. If so, client isn't
   submitting credentials properly.

#. `Verify signing works`_ for the specific `key_id`. If not, likely
   configuration error.

Procedures
==========

Verify Credentials Work
-----------------------

These steps need to be done on a box that can connect to the production
instance. The easiest approach is to have a production instance allocated to you
following the `standard procedure`_.

#. Log into the production instance
#. Clone the Autgraph repo via https: `git clone --depth 1 https://github.com/mozilla-services/autograph.git`
#. Restart autograph via `sudo systemctl start docker-app`. (The box will not
   take production traffic, as it has been removed from the load balancing
   pool.)
#. Extract the Hawk secret from your laptop.
#. Use the go client to test credentail validity. (N.B. for credential
   verificataion, it does not matter if the signature succeeds, so any input
   file is useable):

.. code:: bash

    cd autograph/tools/autograph-client
    go run client.go \
        -t localhost \
        -u hawk-key_id-from-reporter \
        -p hawk-secret-from-laptop \
        -f ../../signer/apk/aligned-two-files.apk \
        -o test.signed.apk \
        -k signer-id-from-reporter-or-hawk-key_id

Verify signing works
--------------------

Use the same setup as for `Verify Credentials Work`_, but ensure you provide the
correct input file format. A correct same should be available in the
`../../signer` subtree.

.. _`standard procedure`: https://mana.mozilla.org/wiki/pages/viewpage.action?pageId=87365053#OnlineHSM(AWS)-get_prod_box_for_hsm_work

.. _`autograph logs`: https://console.cloud.google.com/logs/viewer?project=aws-aws-autograph-p-1535037642&organizationId=442341870013&minLogLevel=0&expandAll=false&timestamp=2019-11-22T14%3A29%3A11.008000000Z&customFacets&limitCustomFacetWidth=true&dateRangeStart=2019-11-21T14%3A29%3A11.258Z&dateRangeEnd=2019-11-22T14%3A29%3A11.258Z&interval=P1D&resource=aws_ec2_instance&scrollTimestamp=2019-11-21T23%3A58%3A48.000000000Z&advancedFilter=resource.type%3D%22aws_ec2_instance%22%0AjsonPayload.code%3D%22401%22
