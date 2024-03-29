import hashlib, base64

def checksum(string):
    #return base64.urlsafe_b85encode(string.encode("utf-8")).decode("utf-8")[:8]
    m = hashlib.md5()
    m.update(string.encode("utf-8"))
    return base64.b85encode(m.digest()).decode("utf-8")




def create_url( command, recipient, amount, operation, openfield):
    if command == "pay":
        openfield_b85_encode = base64.b85encode(openfield.encode("utf-8")).decode("utf-8")
        operation_b85_encode = base64.b85encode(operation.encode("utf-8")).decode("utf-8")

        url_partial = "cwr://{}/{}/{}/{}/{}/".format(command,recipient,amount,operation_b85_encode,openfield_b85_encode)

        url_constructed = url_partial+checksum(url_partial)

        return url_constructed

def read_url(url):

    url_split = url.split("/")
    reconstruct = "cwr://{}/{}/{}/{}/{}/".format(url_split[2],url_split[3],url_split[4],url_split[5],url_split[6],url_split[7])
    operation_b85_decode = base64.b85decode(url_split[5]).decode("utf-8")
    openfield_b85_decode = base64.b85decode(url_split[6]).decode("utf-8")
    if checksum(reconstruct) == url_split[7]:
        url_deconstructed = url_split[2],url_split[3],url_split[4],operation_b85_decode,openfield_b85_decode
        return url_deconstructed
    else:
        return