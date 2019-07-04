echo "Running all tests now."

pocha test/db_test.py
pocha test/server_test.py
pocha test/util_test.py
#pocha test/add_user_test.py # Depricated.
