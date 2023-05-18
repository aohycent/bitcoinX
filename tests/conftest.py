# Pytest looks here for fixtures

import pytest
from curio import Kernel
from curio.monitor import Monitor
from curio.debug import longblock, logcrash


# Taken from curio
@pytest.fixture(scope='session')
def kernel(request):
    k = Kernel(debug=[longblock, logcrash])
    m = Monitor(k)
    request.addfinalizer(lambda: k.run(shutdown=True))
    request.addfinalizer(m.close)
    return k
