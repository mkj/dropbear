#include <time.h>

#define TESTING

#ifdef IOWNANATHLON
#include <unistd.h>
#define SLEEP sleep(4)
#else
#define SLEEP
#endif

#include "tommath.h"

#ifdef TIMER
ulong64 _tt;

#if defined(__i386__) || defined(_M_IX86) || defined(_M_AMD64)
/* RDTSC from Scott Duplichan */
static ulong64 TIMFUNC (void)
   {
   #if defined __GNUC__
      #ifdef __i386__
         ulong64 a;
         __asm__ __volatile__ ("rdtsc ":"=A" (a));
         return a;
      #else /* gcc-IA64 version */
         unsigned long result;
         __asm__ __volatile__("mov %0=ar.itc" : "=r"(result) :: "memory");
         while (__builtin_expect ((int) result == -1, 0))
         __asm__ __volatile__("mov %0=ar.itc" : "=r"(result) :: "memory");
         return result;
      #endif

   // Microsoft and Intel Windows compilers
   #elif defined _M_IX86
     __asm rdtsc
   #elif defined _M_AMD64
     return __rdtsc ();
   #elif defined _M_IA64
     #if defined __INTEL_COMPILER
       #include <ia64intrin.h>
     #endif
      return __getReg (3116);
   #else
     #error need rdtsc function for this build
   #endif
   }
#else
#define TIMFUNC clock
#endif

ulong64 rdtsc(void) { return TIMFUNC() - _tt; }
void reset(void) { _tt = TIMFUNC(); }

#endif

void ndraw(mp_int *a, char *name)
{
   char buf[4096];
   printf("%s: ", name);
   mp_toradix(a, buf, 64);
   printf("%s\n", buf);
}

static void draw(mp_int *a)
{
   ndraw(a, "");
}


unsigned long lfsr = 0xAAAAAAAAUL;

int lbit(void)
{
   if (lfsr & 0x80000000UL) {
      lfsr = ((lfsr << 1) ^ 0x8000001BUL) & 0xFFFFFFFFUL;
      return 1;
   } else {
      lfsr <<= 1;
      return 0;
   }
}

int myrng(unsigned char *dst, int len, void *dat)
{
   int x;
   for (x = 0; x < len; x++) dst[x] = rand() & 0xFF;
   return len;
}


#define DO2(x) x; x;
#define DO4(x) DO2(x); DO2(x);
#define DO8(x) DO4(x); DO4(x);
#define DO(x)  DO8(x); DO8(x);

   char cmd[4096], buf[4096];
int main(void)
{
   mp_int a, b, c, d, e, f;
   unsigned long expt_n, add_n, sub_n, mul_n, div_n, sqr_n, mul2d_n, div2d_n, gcd_n, lcm_n, inv_n,
                 div2_n, mul2_n, add_d_n, sub_d_n, t;
   unsigned rr;
   int i, n, err, cnt, ix, old_kara_m, old_kara_s;

#ifdef TIMER
   ulong64 tt, CLK_PER_SEC;
   FILE *log, *logb, *logc;
#endif

   mp_init(&a);
   mp_init(&b);
   mp_init(&c);
   mp_init(&d);
   mp_init(&e);
   mp_init(&f);

   srand(time(NULL));

#ifdef TESTING
  // test mp_get_int
  printf("Testing: mp_get_int\n");
  for(i=0;i<1000;++i) {
    t = (unsigned long)rand()*rand()+1;
    mp_set_int(&a,t);
    if (t!=mp_get_int(&a)) { 
      printf("mp_get_int() bad result!\n");
      return 1;
    }
  }
  mp_set_int(&a,0);
  if (mp_get_int(&a)!=0)
  { printf("mp_get_int() bad result!\n");
    return 1;
  }
  mp_set_int(&a,0xffffffff);
  if (mp_get_int(&a)!=0xffffffff)
  { printf("mp_get_int() bad result!\n");
    return 1;
  }

  // test mp_sqrt
  printf("Testing: mp_sqrt\n");
  for (i=0;i<10000;++i) { 
    printf("%6d\r", i); fflush(stdout);
    n = (rand()&15)+1;
    mp_rand(&a,n);
    if (mp_sqrt(&a,&b) != MP_OKAY)
    { printf("mp_sqrt() error!\n");
      return 1;
    }
    mp_n_root(&a,2,&a);
    if (mp_cmp_mag(&b,&a) != MP_EQ)
    { printf("mp_sqrt() bad result!\n");
      return 1;
    }
  }

  printf("\nTesting: mp_is_square\n");
  for (i=0;i<100000;++i) {
    printf("%6d\r", i); fflush(stdout);

    /* test mp_is_square false negatives */
    n = (rand()&7)+1;
    mp_rand(&a,n);
    mp_sqr(&a,&a);
    if (mp_is_square(&a,&n)!=MP_OKAY) { 
      printf("fn:mp_is_square() error!\n");
      return 1;
    }
    if (n==0) { 
      printf("fn:mp_is_square() bad result!\n");
      return 1;
    }

    /* test for false positives */
    mp_add_d(&a, 1, &a);
    if (mp_is_square(&a,&n)!=MP_OKAY) { 
      printf("fp:mp_is_square() error!\n");
      return 1;
    }
    if (n==1) { 
      printf("fp:mp_is_square() bad result!\n");
      return 1;
    }

  }
  printf("\n\n");
#endif

#ifdef TESTING 
   /* test for size */
   for (ix = 16; ix < 512; ix++) {
       printf("Testing (not safe-prime): %9d bits    \r", ix); fflush(stdout);
       err = mp_prime_random_ex(&a, 8, ix, (rand()&1)?LTM_PRIME_2MSB_OFF:LTM_PRIME_2MSB_ON, myrng, NULL);
       if (err != MP_OKAY) {
          printf("failed with err code %d\n", err);
          return EXIT_FAILURE;
       }
       if (mp_count_bits(&a) != ix) {
          printf("Prime is %d not %d bits!!!\n", mp_count_bits(&a), ix);
          return EXIT_FAILURE;
       }
   }

   for (ix = 16; ix < 512; ix++) {
       printf("Testing (   safe-prime): %9d bits    \r", ix); fflush(stdout);
       err = mp_prime_random_ex(&a, 8, ix, ((rand()&1)?LTM_PRIME_2MSB_OFF:LTM_PRIME_2MSB_ON)|LTM_PRIME_SAFE, myrng, NULL);
       if (err != MP_OKAY) {
          printf("failed with err code %d\n", err);
          return EXIT_FAILURE;
       }
       if (mp_count_bits(&a) != ix) {
          printf("Prime is %d not %d bits!!!\n", mp_count_bits(&a), ix);
          return EXIT_FAILURE;
       }
       /* let's see if it's really a safe prime */
       mp_sub_d(&a, 1, &a);
       mp_div_2(&a, &a);
       mp_prime_is_prime(&a, 8, &cnt);
       if (cnt != MP_YES) {
          printf("sub is not prime!\n");
          return EXIT_FAILURE;
       }
   }

   printf("\n\n");
#endif

#ifdef TESTING
   mp_read_radix(&a, "123456", 10);
   mp_toradix_n(&a, buf, 10, 3);
   printf("a == %s\n", buf);
   mp_toradix_n(&a, buf, 10, 4);
   printf("a == %s\n", buf);
   mp_toradix_n(&a, buf, 10, 30);
   printf("a == %s\n", buf);
#endif


#if 0
   for (;;) {
      fgets(buf, sizeof(buf), stdin);
      mp_read_radix(&a, buf, 10);
      mp_prime_next_prime(&a, 5, 1);
      mp_toradix(&a, buf, 10);
      printf("%s, %lu\n", buf, a.dp[0] & 3);
   }
#endif

#if 0
{
   mp_word aa, bb;

   for (;;) {
       aa = abs(rand()) & MP_MASK;
       bb = abs(rand()) & MP_MASK;
      if (MULT(aa,bb) != (aa*bb)) {
             printf("%llu * %llu == %llu or %llu?\n", aa, bb, (ulong64)MULT(aa,bb), (ulong64)(aa*bb));
             return 0;
          }
   }
}
#endif

#ifdef TESTING
   /* test mp_cnt_lsb */
   printf("testing mp_cnt_lsb...\n");
   mp_set(&a, 1);
   for (ix = 0; ix < 1024; ix++) {
       if (mp_cnt_lsb(&a) != ix) {
          printf("Failed at %d, %d\n", ix, mp_cnt_lsb(&a));
          return 0;
       }
       mp_mul_2(&a, &a);
   }
#endif

/* test mp_reduce_2k */
#ifdef TESTING
   printf("Testing mp_reduce_2k...\n");
   for (cnt = 3; cnt <= 384; ++cnt) {
       mp_digit tmp;
       mp_2expt(&a, cnt);
       mp_sub_d(&a, 2, &a);  /* a = 2**cnt - 2 */


       printf("\nTesting %4d bits", cnt);
       printf("(%d)", mp_reduce_is_2k(&a));
       mp_reduce_2k_setup(&a, &tmp);
       printf("(%d)", tmp);
       for (ix = 0; ix < 10000; ix++) {
           if (!(ix & 127)) {printf("."); fflush(stdout); }
           mp_rand(&b, (cnt/DIGIT_BIT  + 1) * 2);
           mp_copy(&c, &b);
           mp_mod(&c, &a, &c);
           mp_reduce_2k(&b, &a, 1);
           if (mp_cmp(&c, &b)) {
              printf("FAILED\n");
              exit(0);
           }
        }
    }
#endif


/* test mp_div_3  */
#ifdef TESTING
   printf("Testing mp_div_3...\n");
   mp_set(&d, 3);
   for (cnt = 0; cnt < 1000000; ) {
      mp_digit r1, r2;

      if (!(++cnt & 127)) printf("%9d\r", cnt);
      mp_rand(&a, abs(rand()) % 128 + 1);
      mp_div(&a, &d, &b, &e);
      mp_div_3(&a, &c, &r2);

      if (mp_cmp(&b, &c) || mp_cmp_d(&e, r2)) {
         printf("\n\nmp_div_3 => Failure\n");
      }
   }
   printf("\n\nPassed div_3 testing\n");
#endif

/* test the DR reduction */
#ifdef TESTING
   printf("testing mp_dr_reduce...\n");
   for (cnt = 2; cnt < 128; cnt++) {
       printf("%d digit modulus\n", cnt);
       mp_grow(&a, cnt);
       mp_zero(&a);
       for (ix = 1; ix < cnt; ix++) {
           a.dp[ix] = MP_MASK;
       }
       a.used = cnt;
       mp_prime_next_prime(&a, 3, 0);

       mp_rand(&b, cnt - 1);
       mp_copy(&b, &c);

      rr = 0;
      do {
         if (!(rr & 127)) { printf("%9lu\r", rr); fflush(stdout); }
         mp_sqr(&b, &b); mp_add_d(&b, 1, &b);
         mp_copy(&b, &c);

         mp_mod(&b, &a, &b);
         mp_dr_reduce(&c, &a, (1<<DIGIT_BIT)-a.dp[0]);

         if (mp_cmp(&b, &c) != MP_EQ) {
            printf("Failed on trial %lu\n", rr); exit(-1);

         }
      } while (++rr < 100000);
      printf("Passed DR test for %d digits\n", cnt);
   }
#endif

#ifdef TIMER
      /* temp. turn off TOOM */
      TOOM_MUL_CUTOFF = TOOM_SQR_CUTOFF = 100000;

      reset();
      sleep(1);
      CLK_PER_SEC = rdtsc();

      printf("CLK_PER_SEC == %lu\n", CLK_PER_SEC);
      

      log = fopen("logs/add.log", "w");
      for (cnt = 8; cnt <= 128; cnt += 8) {
         SLEEP;
         mp_rand(&a, cnt);
         mp_rand(&b, cnt);
         reset();
         rr = 0;
         do {
            DO(mp_add(&a,&b,&c));
            rr += 16;
         } while (rdtsc() < (CLK_PER_SEC * 2));
         tt = rdtsc();
         printf("Adding\t\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
         fprintf(log, "%d %9llu\n", cnt*DIGIT_BIT, (((ulong64)rr)*CLK_PER_SEC)/tt); fflush(log);
      }
      fclose(log);

      log = fopen("logs/sub.log", "w");
      for (cnt = 8; cnt <= 128; cnt += 8) {
         SLEEP;
         mp_rand(&a, cnt);
         mp_rand(&b, cnt);
         reset();
         rr = 0;
         do {
            DO(mp_sub(&a,&b,&c));
            rr += 16;
         } while (rdtsc() < (CLK_PER_SEC * 2));
         tt = rdtsc();
         printf("Subtracting\t\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
         fprintf(log, "%d %9llu\n", cnt*DIGIT_BIT, (((ulong64)rr)*CLK_PER_SEC)/tt);  fflush(log);
      }
      fclose(log);

   /* do mult/square twice, first without karatsuba and second with */
mult_test:   
   old_kara_m = KARATSUBA_MUL_CUTOFF;
   old_kara_s = KARATSUBA_SQR_CUTOFF;
   for (ix = 0; ix < 2; ix++) {
      printf("With%s Karatsuba\n", (ix==0)?"out":"");

      KARATSUBA_MUL_CUTOFF = (ix==0)?9999:old_kara_m;
      KARATSUBA_SQR_CUTOFF = (ix==0)?9999:old_kara_s;

      log = fopen((ix==0)?"logs/mult.log":"logs/mult_kara.log", "w");
      for (cnt = 32; cnt <= 288; cnt += 8) {
         SLEEP;
         mp_rand(&a, cnt);
         mp_rand(&b, cnt);
         reset();
         rr = 0;
         do {
            DO(mp_mul(&a, &b, &c));
            rr += 16;
         } while (rdtsc() < (CLK_PER_SEC * 2));
         tt = rdtsc();
         printf("Multiplying\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
         fprintf(log, "%d %9llu\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt);  fflush(log);
      }
      fclose(log);

      log = fopen((ix==0)?"logs/sqr.log":"logs/sqr_kara.log", "w");
      for (cnt = 32; cnt <= 288; cnt += 8) {
         SLEEP;
         mp_rand(&a, cnt);
         reset();
         rr = 0;
         do {
            DO(mp_sqr(&a, &b));
            rr += 16;
         } while (rdtsc() < (CLK_PER_SEC * 2));
         tt = rdtsc();
         printf("Squaring\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
         fprintf(log, "%d %9llu\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt);  fflush(log);
      }
      fclose(log);

   }
expt_test:
  {
      char *primes[] = {
         /* 2K moduli mersenne primes */
         "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151",
         "531137992816767098689588206552468627329593117727031923199444138200403559860852242739162502265229285668889329486246501015346579337652707239409519978766587351943831270835393219031728127",
         "10407932194664399081925240327364085538615262247266704805319112350403608059673360298012239441732324184842421613954281007791383566248323464908139906605677320762924129509389220345773183349661583550472959420547689811211693677147548478866962501384438260291732348885311160828538416585028255604666224831890918801847068222203140521026698435488732958028878050869736186900714720710555703168729087",
         "1475979915214180235084898622737381736312066145333169775147771216478570297878078949377407337049389289382748507531496480477281264838760259191814463365330269540496961201113430156902396093989090226259326935025281409614983499388222831448598601834318536230923772641390209490231836446899608210795482963763094236630945410832793769905399982457186322944729636418890623372171723742105636440368218459649632948538696905872650486914434637457507280441823676813517852099348660847172579408422316678097670224011990280170474894487426924742108823536808485072502240519452587542875349976558572670229633962575212637477897785501552646522609988869914013540483809865681250419497686697771007",
         "259117086013202627776246767922441530941818887553125427303974923161874019266586362086201209516800483406550695241733194177441689509238807017410377709597512042313066624082916353517952311186154862265604547691127595848775610568757931191017711408826252153849035830401185072116424747461823031471398340229288074545677907941037288235820705892351068433882986888616658650280927692080339605869308790500409503709875902119018371991620994002568935113136548829739112656797303241986517250116412703509705427773477972349821676443446668383119322540099648994051790241624056519054483690809616061625743042361721863339415852426431208737266591962061753535748892894599629195183082621860853400937932839420261866586142503251450773096274235376822938649407127700846077124211823080804139298087057504713825264571448379371125032081826126566649084251699453951887789613650248405739378594599444335231188280123660406262468609212150349937584782292237144339628858485938215738821232393687046160677362909315071",
         "190797007524439073807468042969529173669356994749940177394741882673528979787005053706368049835514900244303495954950709725762186311224148828811920216904542206960744666169364221195289538436845390250168663932838805192055137154390912666527533007309292687539092257043362517857366624699975402375462954490293259233303137330643531556539739921926201438606439020075174723029056838272505051571967594608350063404495977660656269020823960825567012344189908927956646011998057988548630107637380993519826582389781888135705408653045219655801758081251164080554609057468028203308718724654081055323215860189611391296030471108443146745671967766308925858547271507311563765171008318248647110097614890313562856541784154881743146033909602737947385055355960331855614540900081456378659068370317267696980001187750995491090350108417050917991562167972281070161305972518044872048331306383715094854938415738549894606070722584737978176686422134354526989443028353644037187375385397838259511833166416134323695660367676897722287918773420968982326089026150031515424165462111337527431154890666327374921446276833564519776797633875503548665093914556482031482248883127023777039667707976559857333357013727342079099064400455741830654320379350833236245819348824064783585692924881021978332974949906122664421376034687815350484991",

         /* DR moduli */
         "14059105607947488696282932836518693308967803494693489478439861164411992439598399594747002144074658928593502845729752797260025831423419686528151609940203368612079",
         "101745825697019260773923519755878567461315282017759829107608914364075275235254395622580447400994175578963163918967182013639660669771108475957692810857098847138903161308502419410142185759152435680068435915159402496058513611411688900243039",
         "736335108039604595805923406147184530889923370574768772191969612422073040099331944991573923112581267542507986451953227192970402893063850485730703075899286013451337291468249027691733891486704001513279827771740183629161065194874727962517148100775228363421083691764065477590823919364012917984605619526140821797602431",
         "38564998830736521417281865696453025806593491967131023221754800625044118265468851210705360385717536794615180260494208076605798671660719333199513807806252394423283413430106003596332513246682903994829528690198205120921557533726473585751382193953592127439965050261476810842071573684505878854588706623484573925925903505747545471088867712185004135201289273405614415899438276535626346098904241020877974002916168099951885406379295536200413493190419727789712076165162175783",
         "542189391331696172661670440619180536749994166415993334151601745392193484590296600979602378676624808129613777993466242203025054573692562689251250471628358318743978285860720148446448885701001277560572526947619392551574490839286458454994488665744991822837769918095117129546414124448777033941223565831420390846864429504774477949153794689948747680362212954278693335653935890352619041936727463717926744868338358149568368643403037768649616778526013610493696186055899318268339432671541328195724261329606699831016666359440874843103020666106568222401047720269951530296879490444224546654729111504346660859907296364097126834834235287147",
         "1487259134814709264092032648525971038895865645148901180585340454985524155135260217788758027400478312256339496385275012465661575576202252063145698732079880294664220579764848767704076761853197216563262660046602703973050798218246170835962005598561669706844469447435461092542265792444947706769615695252256130901271870341005768912974433684521436211263358097522726462083917939091760026658925757076733484173202927141441492573799914240222628795405623953109131594523623353044898339481494120112723445689647986475279242446083151413667587008191682564376412347964146113898565886683139407005941383669325997475076910488086663256335689181157957571445067490187939553165903773554290260531009121879044170766615232300936675369451260747671432073394867530820527479172464106442450727640226503746586340279816318821395210726268291535648506190714616083163403189943334431056876038286530365757187367147446004855912033137386225053275419626102417236133948503",
         "1095121115716677802856811290392395128588168592409109494900178008967955253005183831872715423151551999734857184538199864469605657805519106717529655044054833197687459782636297255219742994736751541815269727940751860670268774903340296040006114013971309257028332849679096824800250742691718610670812374272414086863715763724622797509437062518082383056050144624962776302147890521249477060215148275163688301275847155316042279405557632639366066847442861422164832655874655824221577849928863023018366835675399949740429332468186340518172487073360822220449055340582568461568645259954873303616953776393853174845132081121976327462740354930744487429617202585015510744298530101547706821590188733515880733527449780963163909830077616357506845523215289297624086914545378511082534229620116563260168494523906566709418166011112754529766183554579321224940951177394088465596712620076240067370589036924024728375076210477267488679008016579588696191194060127319035195370137160936882402244399699172017835144537488486396906144217720028992863941288217185353914991583400421682751000603596655790990815525126154394344641336397793791497068253936771017031980867706707490224041075826337383538651825493679503771934836094655802776331664261631740148281763487765852746577808019633679",

         /* generic unrestricted moduli */
         "17933601194860113372237070562165128350027320072176844226673287945873370751245439587792371960615073855669274087805055507977323024886880985062002853331424203",
         "2893527720709661239493896562339544088620375736490408468011883030469939904368086092336458298221245707898933583190713188177399401852627749210994595974791782790253946539043962213027074922559572312141181787434278708783207966459019479487",
         "347743159439876626079252796797422223177535447388206607607181663903045907591201940478223621722118173270898487582987137708656414344685816179420855160986340457973820182883508387588163122354089264395604796675278966117567294812714812796820596564876450716066283126720010859041484786529056457896367683122960411136319",
         "47266428956356393164697365098120418976400602706072312735924071745438532218237979333351774907308168340693326687317443721193266215155735814510792148768576498491199122744351399489453533553203833318691678263241941706256996197460424029012419012634671862283532342656309677173602509498417976091509154360039893165037637034737020327399910409885798185771003505320583967737293415979917317338985837385734747478364242020380416892056650841470869294527543597349250299539682430605173321029026555546832473048600327036845781970289288898317888427517364945316709081173840186150794397479045034008257793436817683392375274635794835245695887",
         "436463808505957768574894870394349739623346440601945961161254440072143298152040105676491048248110146278752857839930515766167441407021501229924721335644557342265864606569000117714935185566842453630868849121480179691838399545644365571106757731317371758557990781880691336695584799313313687287468894148823761785582982549586183756806449017542622267874275103877481475534991201849912222670102069951687572917937634467778042874315463238062009202992087620963771759666448266532858079402669920025224220613419441069718482837399612644978839925207109870840278194042158748845445131729137117098529028886770063736487420613144045836803985635654192482395882603511950547826439092832800532152534003936926017612446606135655146445620623395788978726744728503058670046885876251527122350275750995227",
         "11424167473351836398078306042624362277956429440521137061889702611766348760692206243140413411077394583180726863277012016602279290144126785129569474909173584789822341986742719230331946072730319555984484911716797058875905400999504305877245849119687509023232790273637466821052576859232452982061831009770786031785669030271542286603956118755585683996118896215213488875253101894663403069677745948305893849505434201763745232895780711972432011344857521691017896316861403206449421332243658855453435784006517202894181640562433575390821384210960117518650374602256601091379644034244332285065935413233557998331562749140202965844219336298970011513882564935538704289446968322281451907487362046511461221329799897350993370560697505809686438782036235372137015731304779072430260986460269894522159103008260495503005267165927542949439526272736586626709581721032189532726389643625590680105784844246152702670169304203783072275089194754889511973916207",
         "1214855636816562637502584060163403830270705000634713483015101384881871978446801224798536155406895823305035467591632531067547890948695117172076954220727075688048751022421198712032848890056357845974246560748347918630050853933697792254955890439720297560693579400297062396904306270145886830719309296352765295712183040773146419022875165382778007040109957609739589875590885701126197906063620133954893216612678838507540777138437797705602453719559017633986486649523611975865005712371194067612263330335590526176087004421363598470302731349138773205901447704682181517904064735636518462452242791676541725292378925568296858010151852326316777511935037531017413910506921922450666933202278489024521263798482237150056835746454842662048692127173834433089016107854491097456725016327709663199738238442164843147132789153725513257167915555162094970853584447993125488607696008169807374736711297007473812256272245489405898470297178738029484459690836250560495461579533254473316340608217876781986188705928270735695752830825527963838355419762516246028680280988020401914551825487349990306976304093109384451438813251211051597392127491464898797406789175453067960072008590614886532333015881171367104445044718144312416815712216611576221546455968770801413440778423979",
         NULL
      };
   log = fopen("logs/expt.log", "w");
   logb = fopen("logs/expt_dr.log", "w");
   logc = fopen("logs/expt_2k.log", "w");
   for (n = 0; primes[n]; n++) {
      SLEEP;
      mp_read_radix(&a, primes[n], 10);
      mp_zero(&b);
      for (rr = 0; rr < mp_count_bits(&a); rr++) {
         mp_mul_2(&b, &b);
         b.dp[0] |= lbit();
         b.used  += 1;
      }
      mp_sub_d(&a, 1, &c);
      mp_mod(&b, &c, &b);
      mp_set(&c, 3);
      reset();
      rr = 0;
      do {
         DO(mp_exptmod(&c, &b, &a, &d));
         rr += 16;
      } while (rdtsc() < (CLK_PER_SEC * 2));
      tt = rdtsc();
      mp_sub_d(&a, 1, &e);
      mp_sub(&e, &b, &b);
      mp_exptmod(&c, &b, &a, &e);  /* c^(p-1-b) mod a */
      mp_mulmod(&e, &d, &a, &d);   /* c^b * c^(p-1-b) == c^p-1 == 1 */
      if (mp_cmp_d(&d, 1)) {
         printf("Different (%d)!!!\n", mp_count_bits(&a));
         draw(&d);
         exit(0);
      }
      printf("Exponentiating\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
      fprintf((n < 6) ? logc : (n < 13) ? logb : log, "%d %9llu\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt);
   }
   }
   fclose(log);
   fclose(logb);
   fclose(logc);

   log = fopen("logs/invmod.log", "w");
   for (cnt = 4; cnt <= 128; cnt += 4) {
      SLEEP;
      mp_rand(&a, cnt);
      mp_rand(&b, cnt);

      do {
         mp_add_d(&b, 1, &b);
         mp_gcd(&a, &b, &c);
      } while (mp_cmp_d(&c, 1) != MP_EQ);

      reset();
      rr = 0;
      do {
         DO(mp_invmod(&b, &a, &c));
         rr += 16;
      } while (rdtsc() < (CLK_PER_SEC * 2));
      tt = rdtsc();
      mp_mulmod(&b, &c, &a, &d);
      if (mp_cmp_d(&d, 1) != MP_EQ) {
         printf("Failed to invert\n");
         return 0;
      }
      printf("Inverting mod\t%4d-bit => %9llu/sec, %9llu ticks\n", mp_count_bits(&a), (((ulong64)rr)*CLK_PER_SEC)/tt, tt);
      fprintf(log, "%d %9llu\n", cnt*DIGIT_BIT, (((ulong64)rr)*CLK_PER_SEC)/tt);
   }
   fclose(log);

   return 0;

#endif

   div2_n = mul2_n = inv_n = expt_n = lcm_n = gcd_n = add_n =
   sub_n = mul_n = div_n = sqr_n = mul2d_n = div2d_n = cnt = add_d_n = sub_d_n= 0;

   /* force KARA and TOOM to enable despite cutoffs */
   KARATSUBA_SQR_CUTOFF = KARATSUBA_MUL_CUTOFF = 110;
   TOOM_SQR_CUTOFF      = TOOM_MUL_CUTOFF      = 150;

   for (;;) {
       /* randomly clear and re-init one variable, this has the affect of triming the alloc space */
       switch (abs(rand()) % 7) {
           case 0:  mp_clear(&a); mp_init(&a); break;
           case 1:  mp_clear(&b); mp_init(&b); break;
           case 2:  mp_clear(&c); mp_init(&c); break;
           case 3:  mp_clear(&d); mp_init(&d); break;
           case 4:  mp_clear(&e); mp_init(&e); break;
           case 5:  mp_clear(&f); mp_init(&f); break;
           case 6:  break; /* don't clear any */
       }


       printf("%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu/%4lu ", add_n, sub_n, mul_n, div_n, sqr_n, mul2d_n, div2d_n, gcd_n, lcm_n, expt_n, inv_n, div2_n, mul2_n, add_d_n, sub_d_n);
       fgets(cmd, 4095, stdin);
       cmd[strlen(cmd)-1] = 0;
       printf("%s  ]\r",cmd); fflush(stdout);
       if (!strcmp(cmd, "mul2d")) { ++mul2d_n;
          fgets(buf, 4095, stdin); mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin); sscanf(buf, "%d", &rr);
          fgets(buf, 4095, stdin); mp_read_radix(&b, buf, 64);

          mp_mul_2d(&a, rr, &a);
          a.sign = b.sign;
          if (mp_cmp(&a, &b) != MP_EQ) {
             printf("mul2d failed, rr == %d\n",rr);
             draw(&a);
             draw(&b);
             return 0;
          }
       } else if (!strcmp(cmd, "div2d")) { ++div2d_n;
          fgets(buf, 4095, stdin); mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin); sscanf(buf, "%d", &rr);
          fgets(buf, 4095, stdin); mp_read_radix(&b, buf, 64);

          mp_div_2d(&a, rr, &a, &e);
          a.sign = b.sign;
          if (a.used == b.used && a.used == 0) { a.sign = b.sign = MP_ZPOS; }
          if (mp_cmp(&a, &b) != MP_EQ) {
             printf("div2d failed, rr == %d\n",rr);
             draw(&a);
             draw(&b);
             return 0;
          }
       } else if (!strcmp(cmd, "add")) { ++add_n;
          fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
          mp_copy(&a, &d);
          mp_add(&d, &b, &d);
          if (mp_cmp(&c, &d) != MP_EQ) {
             printf("add %lu failure!\n", add_n);
draw(&a);draw(&b);draw(&c);draw(&d);
             return 0;
          }

          /* test the sign/unsigned storage functions */

          rr = mp_signed_bin_size(&c);
          mp_to_signed_bin(&c, (unsigned char *)cmd);
          memset(cmd+rr, rand()&255, sizeof(cmd)-rr);
          mp_read_signed_bin(&d, (unsigned char *)cmd, rr);
          if (mp_cmp(&c, &d) != MP_EQ) {
             printf("mp_signed_bin failure!\n");
             draw(&c);
             draw(&d);
             return 0;
          }


          rr = mp_unsigned_bin_size(&c);
          mp_to_unsigned_bin(&c, (unsigned char *)cmd);
          memset(cmd+rr, rand()&255, sizeof(cmd)-rr);
          mp_read_unsigned_bin(&d, (unsigned char *)cmd, rr);
          if (mp_cmp_mag(&c, &d) != MP_EQ) {
             printf("mp_unsigned_bin failure!\n");
             draw(&c);
             draw(&d);
             return 0;
          }

       } else if (!strcmp(cmd, "sub")) { ++sub_n;
          fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
          mp_copy(&a, &d);
          mp_sub(&d, &b, &d);
          if (mp_cmp(&c, &d) != MP_EQ) {
             printf("sub %lu failure!\n", sub_n);
draw(&a);draw(&b);draw(&c);draw(&d);
             return 0;
          }
       } else if (!strcmp(cmd, "mul")) { ++mul_n;
          fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
          mp_copy(&a, &d);
          mp_mul(&d, &b, &d);
          if (mp_cmp(&c, &d) != MP_EQ) {
             printf("mul %lu failure!\n", mul_n);
draw(&a);draw(&b);draw(&c);draw(&d);
             return 0;
          }
       } else if (!strcmp(cmd, "div")) { ++div_n;
          fgets(buf, 4095, stdin); mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin); mp_read_radix(&b, buf, 64);
          fgets(buf, 4095, stdin); mp_read_radix(&c, buf, 64);
          fgets(buf, 4095, stdin); mp_read_radix(&d, buf, 64);

          mp_div(&a, &b, &e, &f);
          if (mp_cmp(&c, &e) != MP_EQ || mp_cmp(&d, &f) != MP_EQ) {
             printf("div %lu failure!\n", div_n);
draw(&a);draw(&b);draw(&c);draw(&d); draw(&e); draw(&f);
             return 0;
          }

       } else if (!strcmp(cmd, "sqr")) { ++sqr_n;
          fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
          mp_copy(&a, &c);
          mp_sqr(&c, &c);
          if (mp_cmp(&b, &c) != MP_EQ) {
             printf("sqr %lu failure!\n", sqr_n);
draw(&a);draw(&b);draw(&c);
             return 0;
          }
       } else if (!strcmp(cmd, "gcd")) { ++gcd_n;
          fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
          fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
          mp_copy(&a, &d);
          mp_gcd(&d, &b, &d);
          d.sign = c.sign;
          if (mp_cmp(&c, &d) != MP_EQ) {
             printf("gcd %lu failure!\n", gcd_n);
draw(&a);draw(&b);draw(&c);draw(&d);
             return 0;
          }
       } else if (!strcmp(cmd, "lcm")) { ++lcm_n;
             fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
             mp_copy(&a, &d);
             mp_lcm(&d, &b, &d);
             d.sign = c.sign;
             if (mp_cmp(&c, &d) != MP_EQ) {
                printf("lcm %lu failure!\n", lcm_n);
   draw(&a);draw(&b);draw(&c);draw(&d);
                return 0;
             }
       } else if (!strcmp(cmd, "expt")) {  ++expt_n;
             fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&d, buf, 64);
             mp_copy(&a, &e);
             mp_exptmod(&e, &b, &c, &e);
             if (mp_cmp(&d, &e) != MP_EQ) {
                printf("expt %lu failure!\n", expt_n);
   draw(&a);draw(&b);draw(&c);draw(&d); draw(&e);
                return 0;
             }
       } else if (!strcmp(cmd, "invmod")) {  ++inv_n;
             fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&c, buf, 64);
             mp_invmod(&a, &b, &d);
             mp_mulmod(&d,&a,&b,&e);
             if (mp_cmp_d(&e, 1) != MP_EQ) {
                printf("inv [wrong value from MPI?!] failure\n");
                draw(&a);draw(&b);draw(&c);draw(&d);
                mp_gcd(&a, &b, &e);
                draw(&e);
                return 0;
             }

       } else if (!strcmp(cmd, "div2")) { ++div2_n;
             fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
             mp_div_2(&a, &c);
             if (mp_cmp(&c, &b) != MP_EQ) {
                 printf("div_2 %lu failure\n", div2_n);
                 draw(&a);
                 draw(&b);
                 draw(&c);
                 return 0;
             }
       } else if (!strcmp(cmd, "mul2")) { ++mul2_n;
             fgets(buf, 4095, stdin);  mp_read_radix(&a, buf, 64);
             fgets(buf, 4095, stdin);  mp_read_radix(&b, buf, 64);
             mp_mul_2(&a, &c);
             if (mp_cmp(&c, &b) != MP_EQ) {
                 printf("mul_2 %lu failure\n", mul2_n);
                 draw(&a);
                 draw(&b);
                 draw(&c);
                 return 0;
             }
       } else if (!strcmp(cmd, "add_d")) { ++add_d_n;
              fgets(buf, 4095, stdin); mp_read_radix(&a, buf, 64);
              fgets(buf, 4095, stdin); sscanf(buf, "%d", &ix);
              fgets(buf, 4095, stdin); mp_read_radix(&b, buf, 64);
              mp_add_d(&a, ix, &c);
              if (mp_cmp(&b, &c) != MP_EQ) {
                 printf("add_d %lu failure\n", add_d_n);
                 draw(&a);
                 draw(&b);
                 draw(&c);
                 printf("d == %d\n", ix);
                 return 0;
              }
       } else if (!strcmp(cmd, "sub_d")) { ++sub_d_n;
              fgets(buf, 4095, stdin); mp_read_radix(&a, buf, 64);
              fgets(buf, 4095, stdin); sscanf(buf, "%d", &ix);
              fgets(buf, 4095, stdin); mp_read_radix(&b, buf, 64);
              mp_sub_d(&a, ix, &c);
              if (mp_cmp(&b, &c) != MP_EQ) {
                 printf("sub_d %lu failure\n", sub_d_n);
                 draw(&a);
                 draw(&b);
                 draw(&c);
                 printf("d == %d\n", ix);
                 return 0;
              }
       }
   }
   return 0;
}

