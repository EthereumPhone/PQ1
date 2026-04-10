
Add new object to open62541 server using UAModeler
======================================================

1) Create the information model for opc ua server using UA modeler. Tutorials on UA modeler is not in the scope of this document.

#) Right click on model and export XML

#) Right click on model and export NodesIds

#) Copy the exported xml and csv file to  ``simw-top\demos\opc_ua\opc_ua_server\info_model``. 

#) Modify the filenames in script ``simw-top\demos\opc_ua\opc_ua_server\info_model\generate_info_model_files.py`` if required.

#) Run ::

	python3 generate_info_model_files.py

#) Source files are generated in ``simw-top\demos\opc_ua\opc_ua_server\info_model``

#) Call the new model function from main in server_encryption.c file. Also include the the header files.

#) Update the build files ::

	cd simw-top_build/imx_native_se050_t1oi2c
	cmake .

#) Build open62541 server example