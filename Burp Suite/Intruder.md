**Burp Intruder** is used to automate testing of HTTP requests with multiple payloads. It lets you vary selected parts of a request systematically so you can fuzz input, enumerate values, or identify patterns in the application’s responses.

### **Positions**

When using Burp Suite Intruder to perform an attack, the first step is to examine the positions within the request where we want to insert our payloads. These positions inform Intruder about the locations where our payloads will be introduced.

##### **==Important to Note, 1:==**

When first opening a request in Intruder, Burp Suite automatically attempts to identify the most probable positions where payloads can be inserted. These positions are highlighted in green and enclosed by section marks (`§`). Therefore, make sure to use the `Clear §` button to remove all pre-defined positions, in order to provide a blank canvas where you can define our own positions.

### **Payloads**

#### **1. Payload Sets**

- This section allows us to choose the position for which we want to configure a payload set and select the type of payload we want to use.
- When using attack types that allow only a single payload set (Sniper or Battering Ram), the "Payload Set" dropdown will have only one option, regardless of the number of defined positions.
- If we use attack types that require multiple payload sets (Pitchfork or Cluster Bomb), there will be one item in the dropdown for each position.
- **Note:** When assigning numbers in the "Payload Set" dropdown for multiple positions, follow a top-to-bottom, left-to-right order. For example, with two positions (`username=§pentester§&password=§Expl01ted§`), the first item in the payload set dropdown would refer to the username field, and the second item would refer to the password field

#### **2. Payload Settings/Configuration**

- This section provides options specific to the selected payload type for the current payload set.
- For example, when using the "Simple list" payload type, we can manually add or remove payloads to/from the set using the **Add** text box, **Paste** lines, or **Load** payloads from a file. The **Remove** button removes the currently selected line, and the **Clear** button clears the entire list. 
- Each payload type will have its own set of options and functionality.

#### **3. Payload Processing**

- In this section, we can define rules to be applied to each payload in the set before it is sent to the target.
- For example, we can capitalize every word, skip payloads that match a regex pattern, or apply other transformations or filtering.
#### **4. Payload Encoding**

- The section allows us to customize the encoding options for our payloads.
- By default, Burp Suite applies URL encoding to ensure the safe transmission of payloads. However, there may be cases where we want to adjust the encoding behavior.
- We can override the default URL encoding options by modifying the list of characters to be encoded or unchecking the "URL-encode these characters" checkbox

### **Attack Types**

- **Sniper**: one payload set, one position at a time.
    
- **Battering ram**: one payload set, same payload copied into all positions at once.
    
- **Pitchfork**: multiple payload sets, one set per position, advanced together in parallel.
    
- **Cluster bomb**: multiple payload sets, all payload combinations tested.

### **Identifying Responses of Interest**

In the window that opens when you click `Start attack` you can sort by the columns and also use the filters, **for example** to filter by `Status code 200`. 

1. Look for different `status` code? 
2. If all status codes the same (perhaps due to a redirect), try looking for the response with a different `length`?
3. Also check the `Response Received` column (The time taken to begin receiving a response), look for a different response time, compared to other requests. 
