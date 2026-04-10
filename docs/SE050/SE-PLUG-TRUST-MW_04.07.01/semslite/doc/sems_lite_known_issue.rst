..
    Copyright 2019,2020 NXP


=================================================
 SEMS Lite Known Issue
=================================================



Signature for rerun script is incorrect occasionally
======================================================================

* Issue description: In case of tear (e.g. unexpected power off when upgrading SE), when user tries to load new script, SEMS Lite agent will only allow the re-run script. This script should be the one that is interrupted. But in special case of very early tearing, SEMS Lite agent may expected the user to re-run the script that's already existed in SE before upgrade start.


* Issue workaround: Using sems_lite_get_SignatureofLastScript() to get the signature of the expected script. Find the script and load it.



