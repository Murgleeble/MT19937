import time
import matplotlib.pyplot as plt
import numpy as np

def score(stri: bytes):
    """Evaluate how "English-y" a bytearray is. Returns the average deviation in frequency from standard English of the 10 most common letters (ETAOINRSHD)

    ### Parameters
    1. stri: bytes
        -The bytearray to evaluate

    """
    lenS = len(stri)
    score = 0

    score += abs(.127 - ((stri.count(b'e') + stri.count(b'E'))/lenS))
    score += abs(.091 - ((stri.count(b't') + stri.count(b'T'))/lenS))
    score += abs(.082 - ((stri.count(b'a') + stri.count(b'A'))/lenS))
    score += abs(.075 - ((stri.count(b'o') + stri.count(b'O'))/lenS))
    score += abs(.07 - ((stri.count(b'i') + stri.count(b'I'))/lenS))
    score += abs(.067 - ((stri.count(b'n') + stri.count(b'N'))/lenS))
    score += abs(.06 - ((stri.count(b'r') + stri.count(b'R'))/lenS))
    score += abs(.063 - ((stri.count(b's') + stri.count(b'S'))/lenS))
    score += abs(.061 - ((stri.count(b'h') + stri.count(b'H'))/lenS))
    score += abs(.043 - ((stri.count(b'd') + stri.count(b'D'))/lenS))
    """
    For some reason, addition of extra comparisons to typical english cause more errors than not

    score += .04 - ((stri.count(b'l') + stri.count(b'L'))/lenS)
    score += .028 - ((stri.count(b'c') + stri.count(b'C'))/lenS)
    score += .028 - ((stri.count(b'u') + stri.count(b'U'))/lenS)
    score += .024 - ((stri.count(b'm') + stri.count(b'M'))/lenS)
    score += .024 - ((stri.count(b'w') + stri.count(b'W'))/lenS)
    score += .022 - ((stri.count(b'f') + stri.count(b'F'))/lenS)
    score += .02 - ((stri.count(b'g') + stri.count(b'G'))/lenS)
    score += .02 - ((stri.count(b'y') + stri.count(b'Y'))/lenS)
    score += .019 - ((stri.count(b'p') + stri.count(b'P'))/lenS)
    score += .015 - ((stri.count(b'b') + stri.count(b'B'))/lenS)
    score += .0098 - ((stri.count(b'v') + stri.count(b'V'))/lenS)
    score += .0077 - ((stri.count(b'k') + stri.count(b'K'))/lenS)
    score += .0015 - ((stri.count(b'j') + stri.count(b'J'))/lenS)
    score += .0015 - ((stri.count(b'x') + stri.count(b'X'))/lenS)
    score += .00095 - ((stri.count(b'q') + stri.count(b'Q'))/lenS)
    score += .00074 - ((stri.count(b'z') + stri.count(b'Z'))/lenS) """


    return score/10

class mt19937:
    LOWER_MASK = (1 << 31) -1
    UPPER_MASK = (~LOWER_MASK) & 0xFFFFFFFF
    WORD_SIZE = 32
    DEGREE_OF_RECURRENCE = 624
    MIDDLE = 397
    MT = [0] * DEGREE_OF_RECURRENCE
    index = 1

    def init_mt19937(self, seed: int):
        self.MT[0] = seed
        for i in range(1, self.DEGREE_OF_RECURRENCE):
            self.MT[i] = (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> self.WORD_SIZE-2)) + 1) & 0xFFFFFFFF

    def __init__(self, seed=42):
        self.generator = self.init_mt19937(seed)

    def extract(self):
        ind = self.index
        if ind >= self.DEGREE_OF_RECURRENCE-1:
            if ind == self.DEGREE_OF_RECURRENCE:
                raise Exception("Generator was not seeded")
            self.twist()
        
        y = self.MT[ind]
        y = y ^ ((y >> 11) & 0xFFFFFFFF)
        y = y ^ ((y << 7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ (y >> 18)

        self.index += 1
        return y & 0xFFFFFFFF

    def twist(self):
        for i in range(self.DEGREE_OF_RECURRENCE-1):
            x = (self.MT[i] & self.UPPER_MASK) | (self.MT[(i+1) % self.DEGREE_OF_RECURRENCE] & self.LOWER_MASK)
            xA = x >> 1
            if not (x%2):
                xA = xA ^ 0x9908B0DF
            self.MT[i] = self.MT[(i+self.MIDDLE) % self.DEGREE_OF_RECURRENCE] ^ xA
        self.index = 0

def deterministicRN(seed: int):
    """Generate a random number from a seed that is guaranteed to be function the same every time for each seed
    
    ### Parameters:
    1. seed: int
        -The seed to generate from

    """
    generator = mt19937(seed)
    return generator.extract()

def generateKeystream(seed: int=time.time_ns()):
    """MT19937 keystream generator. Currently generates 8-bit random numbers so that UCF-8 chars can be encoded 1-to-1
    
    ### Parameters:
    1. seed: int=time.time_ns()
        -The seed to generate from.  Defaults to the current machinetime in nanoseconds
    """
    generator = mt19937(seed & 0xFFFF)
    while True:
        yield generator.extract() & 0xFF

def encryptPRNG(plaintext: str):
    """ Using a MT19937 KeyStream, encrypt plaintext. Returns a tuple of (the ciphertext, the seed used) currently for debugging and testing purposes

    ### Parameters:
    1. plaintext: str
        -The plaintext to be encrypted
    
    """
    bytetext = bytearray(plaintext.encode())
    seed = time.time_ns()
    keystream = generateKeystream(seed)
    ciphertext = bytearray()
    usedKeys = []
    for byte in bytetext:
        key = next(keystream)
        usedKeys.append(key)
        ciphertext.append(byte ^ key)
    return ciphertext, seed

def decryptPRNG(ciphertext: bytearray, keystream):
    """ Decrypts ciphertext given the keystream it is derived from using MT19937 PRNG.  Used by the crackMTstreamCipher method

    ### Parameters
    1. ciphertext: bytearray
        -the ciphertext to decrypt
    2. keystream
        -an array of keys used to generate the ciphertext
    
    """
    plaintext = bytearray()
    for i in range(len(ciphertext)):
        plaintext += chr(ciphertext[i] ^ keystream[i]).encode()
    return plaintext

def crackMTstreamCipher(ciphertext: bytearray):
    """ Given a ciphertext that was encrypted using (my) MT19937 PRNG keystream, try to decrypt it.
    Do this by brute-forcing 16-bit keys returning the seed that yielded the best text.  This method of decryption gets exponentially worse over time!

    ### Parameters
    1. ciphertext
        -The ciphertext to decrypt
    
    """
    topScore = 1
    topSeed = None
    topText = None
    for seed in range(pow(2, 16)):
        generator = generateKeystream(seed)
        usedKeys = []
        for i in range(len(ciphertext)):
            usedKeys.append(next(generator))
        scr = score(decryptPRNG(ciphertext, usedKeys))
        if scr < topScore:
            topScore = scr
            topSeed = seed
            topText = decryptPRNG(ciphertext, usedKeys)
    print(f"Best Guess is: {topSeed} which yields:")
    return (bytes(topText))

def runCrackPRNG(plaintext: str):
    """ Given plaintext, will encrypt it then decrypt it and time the time taken to crack the PRNG

    ### Paramters
    1. plaintext: str
        -The string to run the program on
    
    """
    data = encryptPRNG(plaintext)
    encTime = time.time()
    print(f"\n{crackMTstreamCipher(data[0])}\n")
    timer = (time.time()-encTime)/len(data[0])
    print(f"Took {round(timer, 3)} seconds per chr in the text ({round(timer*len(data[0]), 3)} total)\n")
    print(f"\nActual seed was {data[1]} (% 0xFFFF: {data[1] & 0xFFFF})")

def showMTimg(mod: int=256, size: int=100):
    """ Create an image from the MT19937 generator

    ### Parameters
    1. mod : int=256
        -The top of the desired range of random values.  Defaults to 256 because of RBG pixels
    2. size : int=100
        -The side length of the square to generate.  Default to 100 px
    """
    generator = mt19937(time.time_ns())
    mat = []
    for i in range(size):
        row = []
        for j in range(size):
            px = [generator.extract() % mod, generator.extract() % mod, generator.extract() % mod]
            row.append(px)
        mat.append(row)

    plt.imshow((mat), interpolation='none')
    plt.show()

def showMTnormal(mod: int=100, datasize: int=1000):
    """ Create a graph displaying a range of values generated by the MT19937

    ### Paramters
    1. mod : int=100
        -The top of the desired range. Default 100
    2. datasize : int=1000
        -How many random numbers to generate. Default 1000
    
    """
    generator = mt19937(time.time_ns())
    data = [generator.extract() % mod for i in range(datasize)]
    
    mean = np.mean(data)
    var = np.var(data)
    std = np.std(data)
    min = np.amin(data)
    max = np.amax(data)

    plt.plot([i for i in range(len(data))], data, color='r', label=f'Data (Range: 0-{mod-1})')
    plt.axhline(y=mean, color='b', linestyle='--', label=f'Mean: {mean} (Var: {round(var, 2)})')
    plt.axhline(y= mean-std, color='g', linestyle=':', label=f'-σ')
    plt.axhline(y= mean+std, color='g', linestyle=':', label=f'σ')
    plt.legend()
    plt.show()

example1 = "Crazy? I was crazy once. They locked me in a room. A room full of rats. And rats make me crazy"
example2 = "rem ipsum dolor sit amet, cu vix verterem recusabo quaerendum. Ad ius error oportere constituam, luptatum oporteat ex eos, ex omnium albucius sea. Solum mazim nec ei, et ius alii adversarium, an sea tollit reprimique. Dicam indoctum in eos. Cum soluta quidam referrentur ei, mel id ridens elaboraret. Et nobis intellegat eam, tota quaeque evertitur duo in.\nDuo an illum volumus mandamus, alia malis aliquam no quo. Ex agam pericula incorrupte ius. Mea nemore doctus consetetur at, mel cibo electram euripidis id, et latine vidisse nominavi usu. Eos at ullum populo, eu summo reprimique mel.\nId eos iisque offendit, qui in fierent accusata oportere, per duis nemore nominavi ut. Quo idque dicta ut, in appareat invidunt eum, sint affert accumsan est ei. Id nec liber postea voluptaria, te pro quem audiam deserunt, nec ei probo semper detraxit. Vim in iuvaret salutatus democritum."
example3 = "Por lo general, los inmuebles en las mejores zonas de las ciudades suelen ser una inversión \nmás segura que en los barrios. En ellos, las modas, la evolución de la población y otros muchos \nfactores afectan más a la demanda. Por el contrario, las calles de alto nivel suelen tener \nsiempre alta demanda."
