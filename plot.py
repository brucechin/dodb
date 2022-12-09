import matplotlib
matplotlib.rcParams['text.usetex'] = True
import matplotlib.pyplot as plt
#matplotlib inline
import numpy as np
import math
import heapq as pq

x = np.arange(1, 21)
y = [128.64371203268553,
     216.86920221541283,
     289.2891516276327,
     354.9740256182412,
     411.91695764646255,
     462.7092783849562,
     512.371051911858,
     557.0373577771716,
     599.6238672598266,
     641.1060520107715,
     680.5060781075846,
     718.2933902563893,
     753.933207590896,
     788.8604838340881,
     823.3424488540203,
     856.6454332045863,
     889.9172042977277,
     921.4527860006333,
     952.6615036804212,
     983.609042417687]

plt.scatter(x, y)
z = [y[18] + (y[19]-y[18])*(i-19)  for i in x]
plt.plot(x, z, 'm')
plt.xlabel(r'$\log(1/\delta)$')
plt.ylabel(r'$a$')
plt.title(r'$|Y| > a$ with probability at most $\delta$')

plt.savefig('simulation.pdf')
