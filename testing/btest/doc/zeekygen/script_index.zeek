# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; bro -b -X zeekygen.config %INPUT Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-diff test.rst

@TEST-START-FILE zeekygen.config
script_index	zeekygen/*	test.rst
@TEST-END-FILE

@load zeekygen
