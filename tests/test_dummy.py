from main import dummy_var

def test_dummy():
    assert dummy_var == 42

def test_fail():
    assert True is False