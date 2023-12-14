def bdecode(benstr):
    '''objective ye hai ki string(benstr) ko alag alag dictionaries mei todna based on their types'''
    
    '''Firstly we need to define a selector who can decide which function should be triggered'''
    def bdecode_select(benstr,s):
        if benstr[s]=='i':
            return bdecode_int(benstr,s)
        if benstr[s]=='l':
            return bdecode_list(benstr,s)
        if benstr[s]=='d':
            return bdecode_dict(benstr,s)
            
    #string is always in the form 5:Parth
    def bdecode_str(benstr,s):
        '''here from "s" variable the search for string will get started'''
        i=benstr.find(':',s) #this has the index of the colon
        benstr_len=int(benstr[s:i])
        end_index =i+1+benstr_len
        start_index=i+1
        '''here this return will return the decoded benstr and also the last (end) index,which may be used for further decoding'''
        return benstr[start_index:end_index],end_index 
    
    '''the integer is always in the form i1234e'''
    def bdecode_int(benstr,s):
        '''here we need to find the 'e' in the starting '''
        j= benstr.find('e',s)
        return int(benstr[s:j]),j+1
    
    '''List are in the format l4:spami7ee = ['spam',7]'''
    def bdecode_list(benstr,s):
        list =[]
        while benstr[s] !='e':
            element=bdecode_select(benstr,s)
            list.append(element)
        return list,s+1
    
    def bdecode_dict(benstr,s):
        dict ={}
        
        return 0
    return bdecode_select(benstr,0)

def bencode(item):
    '''Here the item can be any decoded values'''
    def bencode_select(item):
        if item == int:
            return bencode_int
        if item == str :
            return bencode_str 
        if item == list :
            return bencode_list 
        if item == dict :
            return bencode_dict 
    
    def bencode_int(i):
        return 'i'+ str(s) +'e'
    def bencode_str(s):
        return str(len(s)) + ':' + s
    def bencode_list(l):
        return 'l' + ''
    def bencode_dict(d):
    
    
    return bencode_select(item)
    
        
        
        
        