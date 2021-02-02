#include "dllexport.h"
#include "version.h"

#include <cstring>
#include <optional>
#include <sodium.h>
#include <sstream>
#include <string_view>
#include <tcl.h>
#include <unordered_map>

// need a macro for compile-time string concatenation
#define theUrlNamespaceName    "::example::cutil::url"
#define theCryptoNamespaceName "::example::cutil::crypto"
static constexpr auto theParentNamespace = "::example::cutil";
static constexpr auto thePackageName     = "example::cutil";
static constexpr auto thePackageVersion  = PROJECT_VERSION;

struct client_data
{
};

// global
client_data theClientData;

std::string_view
get_string(Tcl_Obj* obj)
{
  int  length{ 0 };
  auto cs = Tcl_GetStringFromObj(obj, &length);
  return { cs, static_cast<size_t>(length) };
}

std::optional<long>
get_long(Tcl_Interp* i, Tcl_Obj* obj)
{
  long val;

  if (Tcl_GetLongFromObj(i, obj, &val) != 0)
    return std::nullopt;
  return val;
}

namespace crypto
{
std::string
random_bytes(size_t len)
{
  std::string out;
  out.resize(len);
  randombytes_buf(out.data(), len);
  return out;
}

std::string
password_hash(std::string_view in)
{
  std::string hashed;
  hashed.resize(crypto_pwhash_STRBYTES);
  if (crypto_pwhash_str(hashed.data(),
                        in.data(),
                        in.size(),
                        crypto_pwhash_OPSLIMIT_INTERACTIVE,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE)
      != 0)
  {
    throw std::runtime_error("out of memory");
  }
  hashed.resize(strlen(hashed.c_str()));
  return hashed;
}

bool
password_hash_verify(std::string_view hash, std::string_view pass)
{
  std::string s{ hash.data(), hash.size() };
  return crypto_pwhash_str_verify(s.c_str(), pass.data(), pass.size()) == 0;
}
} // namespace crypto

int
password_hash(ClientData cd, Tcl_Interp* i, int objc, Tcl_Obj* const objv[])
{
  if (objc != 2)
  {
    Tcl_WrongNumArgs(i, objc, objv, "string");
    return TCL_ERROR;
  }
  auto in = get_string(objv[1]);
  try
  {
    auto out = crypto::password_hash(in);
    Tcl_SetObjResult(i, Tcl_NewStringObj(out.c_str(), out.size()));
    return TCL_OK;
  }
  catch (std::exception const&)
  {
    Tcl_AddErrorInfo(i, "could not hash string.");
    return TCL_ERROR;
  }
}

int
password_hash_verify(ClientData     cd,
                     Tcl_Interp*    i,
                     int            objc,
                     Tcl_Obj* const objv[])
{
  if (objc != 3)
  {
    Tcl_WrongNumArgs(i, objc, objv, "string string");
    return TCL_ERROR;
  }
  auto hash = get_string(objv[1]);
  auto pass = get_string(objv[2]);
  auto out  = crypto::password_hash_verify(hash, pass);
  Tcl_SetObjResult(i, Tcl_NewBooleanObj(out));
  return TCL_OK;
}

int
random_bytes(ClientData cd, Tcl_Interp* i, int objc, Tcl_Obj* const objv[])
{
  if (objc != 2)
  {
    Tcl_WrongNumArgs(i, objc, objv, "number of bytes");
    return TCL_ERROR;
  }
  auto len = get_long(i, objv[1]);
  if (! len)
    return TCL_ERROR;

  if (*len < 0)
  {
    Tcl_SetObjResult(i, Tcl_NewStringObj("size must be >= 0", -1));
    return TCL_ERROR;
  }

  auto out = crypto::random_bytes(*len);
  Tcl_SetObjResult(i, Tcl_NewStringObj(out.data(), out.size()));
  return TCL_OK;
}

namespace url
{
std::string
percent_encode(std::string_view in)
{
  // ascii table: https://tools.ietf.org/html/rfc20
  // rfc3986: https://tools.ietf.org/html/rfc3986
  // performs additional encoding of whitespace characters

  static std::unordered_map<char, char const*> map{
    { ' ', "%20" },  { '\t', "%09" }, { '\r', "%0D" }, { '\n', "%0A" },
    { '\f', "%0C" }, { '\v', "%0B" }, { '!', "%21" },  { '#', "%23" },
    { '$', "%24" },  { '%', "%25" },  { '&', "%26" },  { '\'', "%27" },
    { '(', "%28" },  { ')', "%29" },  { '*', "%2A" },  { '+', "%2B" },
    { ',', "%2C" },  { '/', "%2F" },  { ':', "%3A" },  { ';', "%3B" },
    { '=', "%3D" },  { '?', "%3F" },  { '@', "%40" },  { '[', "%5B" },
    { ']', "%5D" },
  };

  std::ostringstream os;

  for (auto const& c: in)
  {
    if (auto p = map.find(c); p != map.end())
      os << p->second;
    else
      os << c;
  }
  return os.str();
}

std::optional<std::string>
percent_decode(std::string_view in)
{
  std::ostringstream os;
  std::string        temp_s{ "XX" };

  for (size_t i = 0; i < in.size(); ++i)
  {
    if (in[i] == '%')
    {
      if (i + 3 > in.size())
        return std::nullopt;

      int value{ 0 };
      temp_s[0] = in[i + 1];
      temp_s[1] = in[i + 2];
      std::istringstream is{ temp_s };
      if (is >> std::hex >> value)
      {
        os << static_cast<char>(value);
        i += 2;
      }
      else
        return std::nullopt;
    }
    else if (in[i] == '+')
      os << ' ';
    else
      os << in[i];
  }
  return os.str();
}
} // namespace url

int
percent_encode(ClientData cd, Tcl_Interp* i, int objc, Tcl_Obj* const objv[])
{
  if (objc != 2)
  {
    Tcl_WrongNumArgs(i, objc, objv, "string");
    return TCL_ERROR;
  }

  auto in  = get_string(objv[1]);
  auto out = url::percent_encode(in);
  Tcl_SetObjResult(i, Tcl_NewStringObj(out.c_str(), out.size()));
  return TCL_OK;
}

int
percent_decode(ClientData cd, Tcl_Interp* i, int objc, Tcl_Obj* const objv[])
{
  if (objc != 2)
  {
    Tcl_WrongNumArgs(i, objc, objv, "string");
    return TCL_ERROR;
  }
  auto in  = get_string(objv[1]);
  auto out = url::percent_decode(in);
  if (out)
  {
    Tcl_SetObjResult(i, Tcl_NewStringObj(out->c_str(), out->size()));
    return TCL_OK;
  }
  else
  {
    Tcl_AddErrorInfo(i, "could not decode string.");
    return TCL_ERROR;
  }
}

extern "C"
{
  DllExport int
  Example_cutil_Init(Tcl_Interp* i)
  {
    if (Tcl_InitStubs(i, TCL_VERSION, 0) == nullptr)
      return TCL_ERROR;

#define urldef(name, func)                                                     \
  Tcl_CreateObjCommand(i,                                                      \
                       theUrlNamespaceName "::" name,                          \
                       (func),                                                 \
                       &theClientData,                                         \
                       nullptr)
#define cryptodef(name, func)                                                  \
  Tcl_CreateObjCommand(i,                                                      \
                       theCryptoNamespaceName "::" name,                       \
                       (func),                                                 \
                       &theClientData,                                         \
                       nullptr)

    auto parent_ns
      = Tcl_CreateNamespace(i, theParentNamespace, nullptr, nullptr);
    auto ns = Tcl_CreateNamespace(i, theUrlNamespaceName, nullptr, nullptr);
    auto ns_crypto
      = Tcl_CreateNamespace(i, theCryptoNamespaceName, nullptr, nullptr);

    urldef("encode", percent_encode);
    urldef("decode", percent_decode);

    cryptodef("pwhash", password_hash);
    cryptodef("pwhash_verify", password_hash_verify);
    cryptodef("random_bytes", random_bytes);

    if (Tcl_Export(i, ns, "*", 0) != TCL_OK)
      return TCL_ERROR;
    if (Tcl_Export(i, ns_crypto, "*", 0) != TCL_OK)
      return TCL_ERROR;

    if (Tcl_Export(i, parent_ns, "*", 0) != TCL_OK)
      return TCL_ERROR;

    Tcl_CreateEnsemble(i, theUrlNamespaceName, ns, 0);
    Tcl_CreateEnsemble(i, theCryptoNamespaceName, ns_crypto, 0);

    Tcl_PkgProvide(i, thePackageName, thePackageVersion);
    return TCL_OK;
#undef urldef
#undef cryptodef
  }

  DllExport int
  Example_cutil_Unload(Tcl_Interp* i, int flags)
  {
    auto ns = Tcl_FindNamespace(i, theParentNamespace, nullptr, 0);
    Tcl_DeleteNamespace(ns);
    return TCL_OK;
  }
}
