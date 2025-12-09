import math
from collections import Counter

ENGLISH_FREQUENCIES = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074
}
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IC_ENGLISH = 0.067
IC_RANDOM = 0.038

class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        self.alphabet = ALPHABET

    def expand_key(self, text_length: int) -> str:
        key = self.key
        idx = 0
        key_len = len(self.key)
        while len(key) < text_length:
            key += self.key[idx]
            idx = (idx + 1) % key_len
        return key[:text_length]

    def decrypt(self, ciphertext: str) -> str:
        key = self.expand_key(len(ciphertext))
        plaintext = ""
        idx = 0
        for char in ciphertext:
            if char in self.alphabet:
                shift = self.alphabet.index(key[idx])
                plaintext += self.alphabet[(self.alphabet.index(char) - shift) % 26]
                idx += 1
            elif char in ALPHABET_UPPER:
                shift = self.alphabet.index(key[idx])
                plaintext += self.alphabet[
                    (self.alphabet.index(char.lower()) - shift) % 26
                ].upper()
                idx += 1
            else:
                plaintext += char
        return plaintext

def clean_text(text: str) -> str:
    return "".join(filter(str.isalpha, text)).lower()

def calculate_ic(text: str) -> float:
    N = len(text)
    if N <= 1: return 0.0

    counts = Counter(text)
    numerator = 0.0
    for char in ALPHABET:
        count = counts.get(char, 0)
        numerator += count * (count - 1)
        
    denominator = N * (N - 1)
    
    return numerator / denominator if denominator > 0 else 0.0

def find_key_length_ic(ciphertext: str, max_key_len=25) -> int:
    cleaned_text = clean_text(ciphertext)
    key_lens_sorted = []
    
    print("Dang tinh IC de tim do dai khoa...")
    
    for key_length in range(2, max_key_len + 1):
        total_ic = 0.0
        
        for i in range(key_length):
            subgroup = cleaned_text[i::key_length]
            total_ic += calculate_ic(subgroup)
            
        average_ic = total_ic / key_length
        
        key_lens_sorted.append((key_length, average_ic, abs(average_ic - IC_ENGLISH)))

    key_lens_sorted.sort(key=lambda x: x[2])
    
    print("\nTop do dai khoa kha thi:")
    for length, avg_ic, diff in key_lens_sorted[:5]:
        print(f"Do dai {length:2d}: IC khoang {avg_ic:.5f}, lech {diff:.5f}")

    best_key_len = key_lens_sorted[0][0]
    return best_key_len

def find_best_caesar_shift(subgroup_text: str) -> str:
    best_shift = 0
    min_chi_squared = float('inf')
    
    text_len = len(subgroup_text)
    if text_len == 0:
        return 'a'

    for shift in range(26):
        chi_squared_sum = 0.0
        
        shifted_counts = Counter()
        for char in subgroup_text:
            shifted_index = (ALPHABET.index(char) - shift) % 26
            shifted_counts[ALPHABET[shifted_index]] += 1
            
        for i in range(26):
            char = ALPHABET[i]
            expected_count = ENGLISH_FREQUENCIES[char] * text_len
            observed_count = shifted_counts.get(char, 0)
            
            if expected_count == 0:
                continue
                
            difference = observed_count - expected_count
            chi_squared_sum += (difference * difference) / expected_count
            
        if chi_squared_sum < min_chi_squared:
            min_chi_squared = chi_squared_sum
            best_shift = shift
            
    return ALPHABET[best_shift]

if __name__ == "__main__":
    
    challenge_ciphertext = """
    Ale xsajiae vj tci nmxpcsmfz lnz jldjmnvxrk lfxhrioc svv xtspeirvh, wslwmnb ghsxfclw, rzpvnmzyz, eny tuppzdvthdif hgczzw cdzvsmklamoiw. Na med jsrz, xul eqelvldjr yiqpyw tj xul fpwpif olna wzxl jomq bm iitzxeigr jsyepruzw nmxpc wlynmphp ophxh—v vrhpx zy wtvxr dlpcl xhz wbbp, dapvio, se jsydjmopwalwd eyenngruhd eoi ldqvaeetvrs jj goi xzyxag fbkc. Esysublbbx stzxomc, ubqly iiiikf oegp zsublg hrdhlvs os goi acvjoprq xypdamoiw bm asla laktruw lqair yinal, lyk xhzwr yiqwlgtdsaz llgl kiqia ymdp as a mmpo htglvsdxl vj tyairkvraeetvrs. Avbt eynpino qlalzwvkizw gv qzolvn ntvymefhp mjzrtiyez, xhz esaicwpje mizhmyd h geixehp eslqe dr huhpczxaihvuk esl raoyel sq pemsoiaji, xzyeldxl, hro eoi ugxvteep kisomaf sq eoi hpqnu wzfs. Mn heaf eynpino gvcmwtgetdsaz, xsp hjtzvypjp hhw vdijlh ld h goixvuylepsn jj rhvessc ldjr, nsgpyrey fl kmgtui om gbzqtn qysompl. Xsp hrcdiaa Irjwxivrf, msc peemkpr, iiwtlzey ma alp pairiey qsfcuiy jj goi dzbp tcvbbks eoi uihryazcsh, wciel xsp oiamx bm xsp kiczeflh hlz aedkulh lrhmnnx goi qphxhzv bm Ql’la—xhz kbkhpdz sf ovhal lyk nunxvji. L abve cinyx hzbpd zrglv esl fldwfmyw Qpily ss Yipoz, ahdpr h gzcyypo sal azfsh fvgr hrytomlvxvvr. Dttmlvvyf, my Ryief qlalzwvky, nshsw hpyi jphtlh mj ale bsqz sq ooi uihryazcsh aih flre ev snz ss alcpl vevpzz: xsp Lpynmnu Jtpshs ase alp gpvtpshz, xsp Hwpcsqlp Xphhorw svv zckmnvvl zsfwz, eny Xnyxlcbw fjv goi htjoey. Xulwp mlpizjf yiqwlgtzh avx zysc ai egaixaa xo zbcsety kiaol obx lwzs tj tevqzel qomey jsyobgt dr ypjp, clmnasejmyr ale dhrh xsla ecombuw slk goiwrxypyjis wilvro eoi gmeil. My nvrtmefa, Ildairi tuppzdvthdif zyns hw Hdrqbmdx hrd Wyqkltdt ziza goi lqairgmsl xscvygc xul ppyz sf mivuglcuetdsa—h gjnsmcvp cysnpzw wciel xsp zsug mf yimzyr iixb uih qvvmn fnzio zu oamqn, alp xvvag wht sq zui’s vggpsyd. Alin gljpp, vuswi ef zexdhva, xsaamyflw uixvs iywpkhoiatiye vv ldfryeetvr (mjofoe zc umrqeah) md laxadrrk, jcplmnb xul wzfs jrjq goi pykpenw pfgwp vj bdvgo eyo kiaol. Fbgs alvskipamgpz imklnzmkp ztimmgbew ryswol nuh xzyel mifwsydpfigmgf, wfrnisoman xsla piai nuh ophxh vvr use zwtonmglw mfa wtvkrz ateomn v gbuxtybsun wcpvtebel eshyrpj. Tiaiauppp, tu Ebmeuhqtn yildkvvrd—Ubhadwz, Jlctzxivrvac, lyk Msgez—alp lmxempvmi td vjtzr qlttnaid vw n mmyls, itzvahp dehxe jj elalck sr kyapwsxlrt. Cinciy, ahvaymfl, sc Uhrnvl ffqmzsmzzw raicyhp pzepl eyo jsmhyapsy hpxh Bsq, dlpcles ciys sc Uhlairnt vpayiszrgz wpahvaombu eyo zyfaieprr, clwemzrk jzc aloni jos cpqico hvcmyp avuol. Vu qzolvn omzlw, esl roombu sq ooi aaxryptql lan iivpgpk fetsak wecpgtgc elptrpsun maaicayitvxvvrd. Dvqe qmrd me xlxaklbymnlspy—vw n jsyepruvxvvr zq vre’n mampfpuge, hizvvtpz, eny prnenj pr tci jvvwo vj tci ypztyn. Stciez iiassrz mg alczbkh olr siyd vj sxmrugp luh mzxnwljdpgs, zbntmytuk pciavqpyh wuxl nz rply-hevxu lbapymeigrz eyo jsnngvvydylws wilvro eoi bmevu. Astsi ehtvymnls ivdhrugp clqadrf lpfdpze, olrzi tyxyimmrz vpqsico lhteytac’s zrqbvtyn uuzwg as fykirnxnuh esl ynfrbdr. Hslxhzv vuxpcwveoiq hw l dwmrdxhhp cphpm, v gljpp zm vewmeal, zc h wyhfbsmn nvrtdrhhxtzu sf zbvzxpyji, tci nmxpcsmfz ssmicd wvoashuh nztjomx nuh xphriik, oymorprg olr nea mlxwzia smqp hrd yinal. Fwammvxrsc, mpsmea ma alp lmxempvmi nzuxiiyrz xz tuwpdvr osap, tsrvp eljwpjxijr, nuh esl inyyeprr sbqai hrzmcp as fdrq wycavwe wilvro xvvtvpvac.
    """
    
    key_length_guess = find_key_length_ic(challenge_ciphertext, max_key_len=25)
    
    if key_length_guess == 0:
        print("Khong tim duoc do dai khoa hop ly. Thu tang max_key_len xem.")
    else:
        print(f"\nChot do dai khoa la: {key_length_guess}\n")

        print("Di tim ki tu cua khoa:")
        
        found_key = ""
        cleaned_ciphertext_for_groups = clean_text(challenge_ciphertext)
        
        for i in range(key_length_guess):
            subgroup = cleaned_ciphertext_for_groups[i::key_length_guess]
            key_char = find_best_caesar_shift(subgroup)
            found_key += key_char
            print(f"Nhom {i+1}: ra chu '{key_char}'")
            
        print(f"\nKhoa tim duoc la: '{found_key}'\n")

        print("Bat dau giai ma...")
        cipher_solver = VigenereCipher(found_key)
        recovered_plaintext = cipher_solver.decrypt(challenge_ciphertext)
        
        print(f"Noi dung giai ma duoc:\n")
        print(recovered_plaintext)