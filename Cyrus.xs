/*
# Copyright (c) 2002 Carnegie Mellon University
# Written by Mark Adamson
#
# C code to glue Perl SASL to Cyrus libsasl.so
#
*/

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <sasl.h>



struct authensasl {
  sasl_conn_t *conn;
  sasl_callback_t *callbacks;
  char *server;
  char *service;
  char *mech;
  char *user;
  char *initstring;
  char *errormsg;
};



struct _perlcontext {
  int id;
  SV *func;
  SV *param;
  int intparam;
};



/*
   This is the wrapper function that calls Perl callback functions. The SASL
   library needs a C function to handle callbacks, and this function forms the
   glue to get from the C library back into Perl. The perlcontext is a wrapper
   around the context given to the "callbacks" method. It tells which Perl 
   function should be called and what parameter to pass it. 
   Different types of callbacks have different "output" parameters to give data
   back to the C library. This function needs to know how to take information
   returned from the Perl callback subroutine and load it back into the output
   parameters for the C library to read.
   Note that if the callback given to the "callbacks" Perl method is really just
   a string or integer, there is no need to jump into a Perl subroutine.
   The value is loaded directly into the output parameters.
*/


int PerlCallback(void *perlcontext, char *arg0, char *arg1, char *arg2)
{
  int i, intparam, count, rc=0;
  unsigned int len=0;
  struct _perlcontext *cp;
  SV *rsv;


  cp = (struct _perlcontext *)perlcontext;

  /* If there is no function to call, just return the "parameter" */
  if (cp->func == NULL) {
    
    switch(cp->id) {
      case SASL_CB_USER:
      case SASL_CB_AUTHNAME:
      case SASL_CB_LANGUAGE:
        if (cp->param==NULL) rc = -1;
        else  {
          *((char **)arg1) = SvPV(cp->param, len);
          if (arg2) *((unsigned *)arg2) = len;
        }
        break;
      default:
        break;
    }
  }

  /* If there is a function, call it */
  else {
    /* Make a new call stack */
    dSP;

    /* We'll be making temporary perl variables */
    ENTER ;
    SAVETMPS ;

    /* Push values onto the new call stack, using temporary perl variables */
    PUSHMARK(SP);
    if (cp->param) XPUSHs( cp->param );
    switch(cp->id) {
      case SASL_CB_USER:
      case SASL_CB_AUTHNAME:
      case SASL_CB_LANGUAGE:
        /* No additional parameters to load */
        break;
      default:
        printf("Authen::SASL::Cyrus:  Don't know how to instate args for callback %d\n", cp->id);
    }
    PUTBACK;

    count = call_sv(cp->func, G_SCALAR);

    /* Refresh the local stack in case the function played with it */
    SPAGAIN;

    /* Rewrite whatever parameters need it */
    if (count != 1) {
      rc = -1;
    }
    else {
      switch(cp->id) {
        case SASL_CB_USER:
        case SASL_CB_AUTHNAME:
        case SASL_CB_LANGUAGE:
          rsv = POPs;
          *((char **)arg1) = SvPV(rsv, len);
          if (arg2) *((unsigned *)arg2) = len;
          break;
        default:
          break;
      }
    }

    /* Final cleanup of the stack, since we may've pop'd one */
    PUTBACK ;

    /* Remember to delete temporary variables */
    FREETMPS ;
    LEAVE ;
  }


  return(rc);
}





static
int PropertyNumber(char *name)
{
  if (!strcasecmp(name, "user"))          return SASL_USERNAME;
  else if (!strcasecmp(name, "ssf"))      return SASL_SSF;
  else if (!strcasecmp(name, "maxout"))   return SASL_MAXOUTBUF;
  else if (!strcasecmp(name, "realm"))    return SASL_REALM;
  else if (!strcasecmp(name, "optctx"))   return SASL_GETOPTCTX;
  else if (!strcasecmp(name, "iplocal"))  return SASL_IP_LOCAL;
  else if (!strcasecmp(name, "sockname")) return SASL_IP_LOCAL;
  else if (!strcasecmp(name, "ipremote")) return SASL_IP_REMOTE;
  else if (!strcasecmp(name, "peername")) return SASL_IP_REMOTE;
  croak("Unknown SASL property: '%s' (user|ssf|maxout|realm|optctx|sockname|peername)\n", name);
  return -1;
}




/* Convert a Perl callback name into a C callback ID */
static
int CallbackNumber(char *name)
{
  if (!strcasecmp(name, "user"))          return(SASL_CB_USER);
  else if (!strcasecmp(name, "auth"))     return(SASL_CB_AUTHNAME);
  else if (!strcasecmp(name, "language")) return(SASL_CB_LANGUAGE);

  croak("Unknown callback: '%s'. (user|auth|language)\n", name);
}






/*
   Fill the passed callback action into the passed Perl/SASL callback. This
   is called either from ExtractParentCallbacks() when the "new" method is
   called, or from callbacks() when that method is called directly.
*/

static
void AddCallback(
  char *name,
  SV *action,
  struct _perlcontext *pcb,
  sasl_callback_t *cb
  )
{
  pcb->id = CallbackNumber(name);

  if (SvROK(action)) {     /*   user =>  <ref>  */
    action = SvRV(action);

    if (SvTYPE(action) == SVt_PVCV) {   /* user => sub { },  user => \&func */
      pcb->func = action;
      pcb->param = NULL;
    }

    else if (SvTYPE(action) == SVt_PVAV) {   /* user => [ \&func, $param ] */
      pcb->func = av_shift((AV *)action);
      pcb->param = av_shift((AV *)action);
    }
    else
      croak("Unknown reference parameter to %s callback.\n", name);
  }
  else if (SvTYPE(action) == SVt_PV) {   /*  user => $param */
    pcb->func = NULL;
    pcb->param = action;
  }
  else if (SvTYPE(action) == SVt_IV) {   /*  user => 1 */
    pcb->func = NULL;
    pcb->param = NULL;
    pcb->intparam = SvIV(action);
  }
  else
    croak("Unknown parameter to %s callback.\n", name);

  /* Write the C SASL callback */
  cb->id = pcb->id;
  cb->proc = PerlCallback;
  cb->context = pcb;
}





/*
   Take the callback stored in the parent object and install them into the
   current *sasl object.  This is called from the "new" method.
*/

static
void ExtractParentCallbacks(SV *parent, struct authensasl *sasl)
{
  char *key;
  int count=0;
  long l;
  struct _perlcontext *pcb;
  SV **hashval, *val;
  HV *hash=NULL;
  HE *iter;

  /* Make sure parent is a ref to a hash (with keys like "mechanism"
     and "callback") */
  if (!parent) return;
  if (!SvROK(parent)) return;
  if (SvTYPE(SvRV(parent)) != SVt_PVHV) return;
  hash = (HV *)SvRV(parent);

  /* Get the parent's callbacks */
  hashval = hv_fetch(hash, "callback", 8, 0);
  if (!hashval || !*hashval) return;
  val = *hashval;

  /* Parent's callbacks are another hash (with keys like "user" and "auth") */
  if (!SvROK(val)) return;
  if (SvTYPE(SvRV(val)) != SVt_PVHV) return;
  hash = (HV *)SvRV(val);

  /* Run through all of parent's callback types, counting them */
  hv_iterinit(hash);
  for (iter=hv_iternext(hash);  iter;  iter=hv_iternext(hash)) count++;

  /* Allocate space for the callbacks */
  if (sasl->callbacks) {
    free(sasl->callbacks->context);
    free(sasl->callbacks);
  }
  pcb = (struct _perlcontext *)malloc(count * sizeof(struct _perlcontext));
  if (pcb == NULL)  croak("Out of memory\n");

  l = (count + 1) * sizeof(sasl_callback_t);
  sasl->callbacks = (sasl_callback_t *)malloc(l);
  if (sasl->callbacks == NULL) croak("Out of memory\n");
  memset(sasl->callbacks, 0, l);


  /* Run through all of parent's callback types, fill in the sasl->callbacks */
  hv_iterinit(hash);
  for (count=0,iter=hv_iternext(hash);  iter;  iter=hv_iternext(hash),count++){
    key = hv_iterkey(iter, &l);
    val = hv_iterval(hash, iter);
    AddCallback(key, val, &pcb[count], &sasl->callbacks[count]);
  }
  sasl->callbacks[count].id = SASL_CB_LIST_END;
  sasl->callbacks[count].context = pcb;

  return;
}




MODULE=Authen::SASL::Cyrus      PACKAGE=Authen::SASL::Cyrus




struct authensasl *
client_new(pkg, parent, service, host, ...)
    char *pkg
    SV *parent
    char *service
    char *host
  CODE:
  {
    const char *mech=NULL;
    char *init=NULL;
    int rc;
    unsigned int initlen=0;
    struct authensasl *sasl;
    HV *hash;
    SV **hashval, *val;

    sasl = (struct authensasl *)malloc(sizeof(struct authensasl));
    if (sasl == NULL) croak("Out of memory\n");
    memset(sasl, 0, sizeof(struct authensasl));

    if (!host || !*host) {
      if (!sasl->errormsg) sasl->errormsg = "Need a 'hostname' in client_new()";
    }
    else
      sasl->server = strdup(host);

    if (!service || !*service) {
      if (!sasl->errormsg) sasl->errormsg = "Need a 'service' name in client_new()";
    }
    else
      sasl->service = strdup(service);


    /* Extract callback info from the parent object */
    ExtractParentCallbacks(parent, sasl);

    /* Extract mechanism info from the parent object */
   if (parent && SvROK(parent) && (SvTYPE(SvRV(parent)) == SVt_PVHV)) {
     hash = (HV *)SvRV(parent);
     hashval = hv_fetch(hash, "mechanism", 9, 0);
     if (hashval  && *hashval && SvTYPE(*hashval) == SVt_PV) {
       if (sasl->mech) free(sasl->mech);
       sasl->mech = strdup(SvPV_nolen(*hashval));
     }
   }

    sasl_client_init(NULL);
    rc = sasl_client_new(sasl->service, sasl->server, sasl->callbacks, 1, &sasl->conn);
    if (rc != SASL_OK) {
      if (!sasl->errormsg) sasl->errormsg = "sasl_client_new failed";
    }
    else {
      rc = sasl_client_start(sasl->conn, sasl->mech, NULL, NULL, &init, &initlen, &mech);
      if (rc == SASL_NOMECH) {
        if (!sasl->errormsg) 
          sasl->errormsg = "No mechanisms available (did you set all needed callbacks?)";
      }
      else if ((rc != SASL_OK) && (rc != SASL_CONTINUE)) {
        if (!sasl->errormsg) sasl->errormsg = "sasl_client_start failed";
      }
      else {
        if (init) sasl->initstring = strdup(init);
      }
    }
    RETVAL = sasl;
  }
  OUTPUT:
    RETVAL




char *
client_start(sasl)
    struct authensasl *sasl
  CODE:
    RETVAL = sasl->initstring;
  OUTPUT:
    RETVAL





char *
client_step(sasl, instring)
    struct authensasl *sasl
    char *instring
  PPCODE:
  {
    char *outstring=NULL;
    int rc;
    unsigned int inlen, outlen=0;


    if (sasl->errormsg) {
      XSRETURN_UNDEF;
    }
    SvPV(ST(1),inlen);

    rc = sasl_client_step(sasl->conn, instring, inlen, NULL, &outstring, &outlen);
    if ((rc != SASL_OK) && (rc != SASL_CONTINUE)) {
      sasl->errormsg = "sasl_client_step failed";
      XSRETURN_UNDEF;
    }
    XPUSHp(outstring, outlen);
  }




int
callback(sasl, ...)
    struct authensasl *sasl
  CODE:
  {
    SV *action;
    char *name;
    int x, count;
    struct _perlcontext *pcb;


    /* Asking if a given callback exists */
    if (items == 2) {
      RETVAL = 0;
      if (sasl->callbacks) {
        name = SvPV_nolen(ST(1));
        x = CallbackNumber(name);

        /* Check the installed callbacks for the requested ID */
        for (count=0; sasl->callbacks[count].id != SASL_CB_LIST_END; count++) {
          if (sasl->callbacks[count].id == x) {
            RETVAL = 1;
            break;
          }
        }
      }
      ST(0) = sv_newmortal();
      sv_setiv(ST(0), (int)RETVAL);
      XSRETURN(1);
    }

    /* Prepare space for the callback list */
    if (sasl->callbacks) {
      free(sasl->callbacks->context);
      free(sasl->callbacks);
    }
    count = (items - 1) / 2;
    x = (count + 1) * sizeof(sasl_callback_t);
    pcb = (struct _perlcontext *)malloc(count * sizeof(struct _perlcontext));
    if (pcb == NULL) {
      croak("Out of memory\n");
    }
    sasl->callbacks = (sasl_callback_t *)malloc(x);
    if (sasl->callbacks == NULL) {
      croak("Out of memory\n");
    }
    memset(sasl->callbacks, 0, x);

    /* Fill in the callbacks */
    for(x=0; x<count; x++) {
      /* Convert the callback name into a SASL ID number */
      if (SvTYPE(ST(1+x*2)) != SVt_PV) {
        croak("callbacks: Unknown key given in position %d\n", x);
      }
      name = SvPV_nolen(ST(1+x*2));
      action = ST(2+x*2);
      AddCallback(name, action, &pcb[x], &sasl->callbacks[x]);
    }
    sasl->callbacks[count].id = SASL_CB_LIST_END;
    sasl->callbacks[count].context = pcb;

    RETVAL = count;
  }
  OUTPUT:
    RETVAL




char *
error(sasl)
    struct authensasl *sasl
  CODE:
    RETVAL = sasl->errormsg;
    sasl->errormsg = NULL;
  OUTPUT:
    RETVAL



int
code(sasl)
    struct authensasl *sasl
  CODE:
    if (sasl->errormsg) RETVAL=1;
    else RETVAL=0;
  OUTPUT:
    RETVAL



char *
mechanism(sasl)
    struct authensasl *sasl
  CODE:
    RETVAL = sasl->mech;
  OUTPUT:
    RETVAL



char *
host(sasl, ...)
    struct authensasl *sasl
  CODE:
    if (items > 1) {
      if (sasl->server) free(sasl->server);
      sasl->server = strdup(SvPV_nolen(ST(1)));
    }
    RETVAL = sasl->server;
  OUTPUT:
    RETVAL



char *
user(sasl, ...)
    struct authensasl *sasl
  CODE:
    if (items > 1) {
      if (sasl->user) free(sasl->user);
      sasl->user = strdup(SvPV_nolen(ST(1)));
    }
    RETVAL = sasl->user;
  OUTPUT:
    RETVAL



char *
service(sasl, ...)
    struct authensasl *sasl
  CODE:
    if (items > 1) {
      if (sasl->service) free(sasl->service);
      sasl->service = strdup(SvPV_nolen(ST(1)));
    }
    RETVAL = sasl->service;
  OUTPUT:
    RETVAL




int
property(sasl, ...)
    struct authensasl *sasl
  PPCODE:
  {
    void *value=NULL;
    char *name;
    int rc, x, propnum=-1;
    SV *prop;


    RETVAL = 0;

    if (!sasl->conn) {
      if (!sasl->errormsg) sasl->errormsg="sasl_setproperty called on uninitialized connection";
      RETVAL = 1;
      items = 0;
    }

    /* Querying the value of a property */
    if (items == 2) {
      name = SvPV_nolen(ST(1));
      propnum = PropertyNumber(name);
      rc = sasl_getprop(sasl->conn, propnum, &value);
      if (rc != SASL_OK) XSRETURN_UNDEF;
      switch(propnum){
        case SASL_USERNAME:
        case SASL_REALM:
          XPUSHp( (char *)value, strlen((char *)value));
          break;
        case SASL_SSF:
        case SASL_MAXOUTBUF:
          XPUSHi((int *)value);
          break;
        case SASL_IP_LOCAL:
        case SASL_IP_REMOTE:
          XPUSHp( (char *)value, sizeof(struct sockaddr_in));
          break;
        default: 
          XPUSHi(-1);
      }
      XSRETURN(1);
    }

    /* Fill in the properties */
    for(x=1; x<items; x+=2) {

      prop = ST(x);
      value = (void *)SvPV_nolen( ST(x+1) );

      if (SvTYPE(prop) == SVt_IV) {
        propnum = SvIV(prop);
      }
      else if (SvTYPE(prop) == SVt_PV) {
        name = SvPV_nolen(prop);
        propnum = PropertyNumber(name);
      }
      rc = sasl_setprop(sasl->conn, propnum, value);
      if (rc != SASL_OK) {
        if (!sasl->errormsg) sasl->errormsg="sasl_setprop failed";
        RETVAL = 1;
      }
    }
  }





void
DESTROY(sasl)
    struct authensasl *sasl
  CODE:
    if (sasl->conn)  sasl_dispose(&sasl->conn);
    if (sasl->callbacks) {
      free(sasl->callbacks->context);
      free(sasl->callbacks);
    }
    if (sasl->service)   free(sasl->service);
    if (sasl->mech)      free(sasl->mech);
    if (sasl->errormsg)  free(sasl->errormsg);
    if (sasl->initstring)free(sasl->initstring);
    free(sasl);


