// Reorders the instructions of the current function selected and creates a file with the code without NOPs and useless LEAs.
// Furthermore detects single hex ascii characters and converts them.
// It also adds label from conditional jumps (experimental).
//@author Giacomo Lorenzo Rossi
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class FunctionSimplifier extends GhidraScript {

    private static final String[] conditionalJumps = {"JAE", "JB", "JBE", "JC", "JE", "JZ", "JG", "JGE", "JL", "JLE",
            "JNA", "JNAE", "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE", "JNL", "JNLE", "JNO", "JNP",
            "JNS", "JNZ", "JO", "JP", "JPE", "JPO", "JS"};

    public static void main(String[] args) {
        // only a simple test...
        System.out.println(asciiToChar("00451a51           6a77 PUSH 0x77"));
        System.out.println(contains2CharHex("00451a51           6a77 PUSH 0x77"));
        System.out.println(contains2CharHex("00451a51           6a77 PUSH 0x77\n"));
        System.out.println(contains2CharHex("00451a51           6a77 PUSH 0x77444"));
        System.out.println(contains2CharHex("00451a51           6a77 PUSH 0x77 "));
    }

    @Override
    public void run() throws Exception {
        Optional<Function> currentFuncOpt = Optional.ofNullable(getFunctionContaining(currentAddress));
        if (currentFuncOpt.isEmpty()) {
            println("The address at " + currentAddress + " is not in a function");
            return;
        }
        Function function = currentFuncOpt.get();

        printf("Simplifying function %s at address %s\n", function.getName(), function.getEntryPoint().toString());

        var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);

        // ricavo le istruzioni della funzione corrente.
        List<InstructionInfo> ii = getInstructionsOfFunction(instructions);

        // raggruppo le istruzioni tra un salto e l'altro.
        var groups = groupInstructions(ii);

        // riordino i gruppi in ordine, seguendo i salti
        var orderedGroups = reorderInstructionGroups(groups);

        File f = new File(String.format("%s/Desktop/%s.txt", System.getProperty("user.home"), function.getName()));
        f.createNewFile();
        println("Created output file in " + f.getAbsolutePath());

        // Vengono aggiornati i salti condizionati. Produco la lista di indirizzi e label da aggiungere
        List<Map<Address, String>> mapList = orderedGroups.stream()
                .map(InstructionGroup::updateConditionalJumps)
                .toList();
        //trasformo la lista di gruppi in una mappa
        Map<Address, InstructionGroup> mapInstructionGroup = orderedGroups.stream().collect(Collectors.toMap(InstructionGroup::getGroupAddress, i -> i));
        printList(mapInstructionGroup.entrySet().stream().limit(10).toList());
        // Trovo e aggiungo le label dai salti condizionati CHE VANNO MODIFICATI (non tutti i gruppi)
        Map<Address, String> addressDaAggiungere = new HashMap<>();
        for (Map<Address, String> addressStringMap : mapList) {
            for (var addr_str : addressStringMap.entrySet()) {
                Optional<Address> address = firstValidAddressFrom(addr_str.getKey(), mapInstructionGroup);
                address.ifPresent(value -> addressDaAggiungere.put(value, addr_str.getValue()));
            }
        }

        try (BufferedWriter bf = new BufferedWriter(new FileWriter(f))) {
            // Rimuovo NOP e LEA dai gruppi.
            // Infine rimuovo i gruppi formati da soli salti incondizionati
            var cleanedInstructions = orderedGroups.stream()
                    // .map(i -> i.updateConditionalJumps())
                    .map(InstructionGroup::removeUselessInstructions)
                    .filter(InstructionGroup::hasUsefulIntruction)
                    .flatMap(ig -> ig.getInstructions().stream())
                    .filter(i -> !i.isJMP())
                    .toList();

            // tutte le istruzioni filtrate
            for (var instruction : cleanedInstructions) {
                Address address = instruction.getAddress();
                if (addressDaAggiungere.containsKey(address)) {
                    // imposto la label prima dell'istruzione
                    bf.append("\t\t\t")
                            .append(addressDaAggiungere.get(address))
                            .append("\n");
                }


                bf.append(instruction.toString()).append("\n");
                var j = cleanedInstructions.indexOf(instruction);
                if (j % 100 == 0 || j == cleanedInstructions.size() - 1) {
                    bf.flush();
                }
            }
        } catch (IOException io) {
            io.printStackTrace();
        }
        // L'unico problema sono i salti condizionati, che disordinano un po' le istruzioni, ma basta seguire l'indirizzo di salto.
    }

    private static boolean contains2CharHex(String input) {
        return !input.matches(".*0x[0-9a-f]{3}") && input.matches(".*0x[0-9a-f]{2}([ \\n])*");
    }

    private static String asciiToChar(String code) {
        if (contains2CharHex(code)) {
            int i = code.indexOf("0x");
            String hex = code.substring(i + 2, i + 4);
            try {
                int group = Integer.parseInt(hex, 16);
                char c = (char) group;
                return code.replaceFirst("0x[0-9a-f]{2}", String.format("'%c'", c));
            } catch (Exception e) {
                System.out.println("error");
                return code;
            }

        }
        return code;
    }

    public List<InstructionInfo> getInstructionsOfFunction(InstructionIterator instructions) {
        List<InstructionInfo> ii = new ArrayList<>();
        while (instructions.hasNext()) {
            var ins = new InstructionInfo(instructions.next());
            ii.add(ins);
        }
        return ii;
    }

    public List<InstructionGroup> groupInstructions(List<InstructionInfo> ii) {
        List<InstructionGroup> groups = new ArrayList<>();
        var bit = ii.iterator();
        while (bit.hasNext()) {
            // creo un nuovo gruppo di istruzioni
            InstructionGroup ig = new InstructionGroup(null);
            InstructionInfo inst;
            do {
                // prendo la prossima istruzione e la metto nel gruppo
                inst = bit.next();
                ig.add(inst);
                // se l'istruzione corrente e' un salto JMP esco dal while...
            } while (!inst.isJMP());
            // ...e aggiungo il gruppo alla lista.
            groups.add(ig);
        }
        return groups;
    }

    public List<InstructionGroup> reorderInstructionGroups(List<InstructionGroup> groups) {
        // Ora riordino i gruppi di istruzioni
        List<InstructionGroup> orderedGroups = new ArrayList<>();
        Optional<InstructionGroup> currentGroup = groups.stream().findFirst();
        if (currentGroup.isPresent()) {
            var current = currentGroup.get();
            orderedGroups.add(current);
            groups.remove(current);
            boolean continua = false;
            do {
                var nextAddrOpt = current.getAddressOfNextGroup();
                if (nextAddrOpt.isPresent()) {
                    var nextAddr = nextAddrOpt.get();

                    Optional<InstructionGroup> nextGroup = groups.stream()
                            .filter(g -> g.getGroupAddress().equals(nextAddr))
                            .findFirst();

                    if (nextGroup.isPresent()) {
                        continua = true;
                        var newGroup = nextGroup.get();
                        orderedGroups.add(newGroup);
                        groups.remove(newGroup);
                        current = newGroup;
                    } else {
                        continua = false;
                    }
                }
            } while (continua);
            groups.stream().findFirst().ifPresent(orderedGroups::add);
        }
        return orderedGroups;
    }

    /**
     * Restituisce l'indirizzo della prima istruzione valida a partire dall'indirizzo dato.
     * La lista di gruppi deve avere anche NOP e LEA
     *
     * @param address   indirizzo di partenza
     * @param groupList gruppi
     * @return indirizzo di arrivo
     */
    public Optional<Address> firstValidAddressFrom(Address address, Map<Address, InstructionGroup> groupList) {
        // Trovo il gruppo che contiene l'istruzione con address dato in input.
        Optional<InstructionGroup> instructionGroup = groupList.values()
                .stream()
                .filter(istr -> istr.containsAddress(address))
                .findFirst();

        if (instructionGroup.isEmpty()) {
            println("Can't find group for address " + address + " in list ");
            return Optional.empty();
        }

        int max = groupList.size();
        int i = 0;
        while (instructionGroup.isPresent() && i < max) {
            InstructionGroup currentGroup = instructionGroup.get();
            if (currentGroup.hasUsefulIntruction()) {
                Optional<InstructionInfo> firstUsefulInstruction = currentGroup.getFirstUsefulInstructionOrJump();
                println("Useful: " + firstUsefulInstruction);
                if (firstUsefulInstruction.isPresent() && !firstUsefulInstruction.get().isJMP()) {
                    return firstUsefulInstruction.map(InstructionInfo::getAddress);
                } else if (currentGroup.getAddressOfNextGroup().isPresent()) {
                    var newAddress = currentGroup.getAddressOfNextGroup().get();
                    instructionGroup = Optional.ofNullable(groupList.get(newAddress));
                }
            } else if (currentGroup.getAddressOfNextGroup().isPresent()) {
                instructionGroup = findInstructionGroup(groupList, currentGroup.getAddressOfNextGroup().get());
            }
            i++;
        }
        println("Can't find address of first useful instruction from " + address.toString());
        return Optional.empty();
    }

    public <T> void printList(List<T> list) {
        for (var e : list) {
            println(e.toString());
        }
    }

    public Optional<InstructionGroup> findInstructionGroup(Map<Address, InstructionGroup> map, Address addr) {
        return Optional.ofNullable(map.get(addr));
    }

    static final class InstructionInfo {
        private final String address;
        private String code;
        private final int numOperands;
        private final List<Object> operandRepresentations = new ArrayList<>();
        private String bytes;
        private final Instruction instruction;

        public InstructionInfo(Instruction i) {
            this.address = i.getAddressString(false, true);
            this.code = asciiToChar(i.toString());
            this.numOperands = i.getNumOperands();
            try {
                StringBuilder sb = new StringBuilder();
                for (byte aByte : i.getBytes()) {
                    sb.append(String.format("%x", aByte));
                }
                this.bytes = sb.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
            for (int j = 0; j < this.numOperands; j++) {
                operandRepresentations.add(i.getDefaultOperandRepresentationList(j));
            }
            this.instruction = i;
        }


        /**
         * @return è inutile se è un NOP o una LEA. Non controlla se è un salto.
         */
        public boolean isUseless() {
            return isNop() || isUselessLea();
        }

        public Address getAddress() {
            return this.instruction.getAddress();
        }

        public boolean isNop() {
            return code.contains("NOP");
        }

        public boolean isUselessLea() {
            return (code.contains("LEA") && withSameTwoOperands());
        }

        public boolean isJMP() {
            return code.contains("JMP");
        }

        public boolean isConditionalJump() {
            return Arrays.asList(conditionalJumps).contains(instruction.getMnemonicString());
        }

        /**
         * @return l'oggetto Address restituito dall' Instruction di Ghidra per l'istruzione corrente
         */
        public Optional<Address> getJumpAddress() {
            if (this.isJMP() || this.isConditionalJump()) {
                return Optional.ofNullable(instruction.getAddress(0));
            }
            return Optional.empty();
        }

        /**
         * Cambia la label del salto. Se l'istruzione non è un salto condizionato non fa nulla
         * @param jumpLabel etichetta da sostituire all'indirizzo del salto.
         */
        public Optional<Address> setConditionalJumpAddressString(String jumpLabel) {
            if (isConditionalJump()) {
                var jmpCond = instruction.getMnemonicString();
                this.code = (jmpCond + " " + jumpLabel);
                return Optional.ofNullable(instruction.getOperandReferences(0)[0].getToAddress());
            }
            return Optional.empty();
        }

        public String toString() {
            return String.format("%s %14s %s", this.address, this.bytes, this.code);
        }

        public Optional<String> getFirstOperand() {
            if (numOperands >= 1) {
                return Optional.ofNullable(instruction.getDefaultOperandRepresentation(0));
            }
            return Optional.empty();
        }

        public Optional<String> getSecondOperand() {
            if (numOperands >= 2) {
                return Optional.ofNullable(instruction.getDefaultOperandRepresentation(1));
            }
            return Optional.empty();
        }

        public boolean withSameTwoOperands() {
            Optional<String> firstOperand = getFirstOperand();
            Optional<String> secondOperand = getSecondOperand();
            if (firstOperand.isPresent() && secondOperand.isPresent()) {
                var op1 = firstOperand.get();
                var op2 = secondOperand.get();

                if (op2.contains("[")) {
                    op2 = op2.substring(1, 4);
                    // System.out.println(op2);
                }

                return op1.equals(op2);
            }
            return false;
        }
    }

    // insieme di istruzioni che termina con un salto.
    static final class InstructionGroup {
        private Address address;
        private List<InstructionInfo> instructions;
        private static int counterLabel = 1;

        public InstructionGroup(InstructionInfo i) {
            this.instructions = new ArrayList<>();
            if (i != null) {
                this.instructions.add(i);
                this.address = i.getAddress();
                // System.out.println(i.getAddress().toString());
            }
        }

        public List<InstructionInfo> getInstructions() {
            return this.instructions;
        }

        public InstructionGroup removeUselessInstructions() {
            this.instructions = this.instructions.stream().filter(i -> !i.isUseless()).toList();
            return this;
        }

        public void add(InstructionInfo i) {
            this.instructions.add(i);
        }

        public Address getGroupAddress() {
            if (this.address == null) {
                this.address = instructions.get(0).getAddress();
            }
            return this.address;
        }

        /**
         * Non ha istruzioni utili se:
         * - contiene solo un salto JMP
         * - contiene solo JMP e NOP
         * - contiene solo JMP e LEA (e due par =)
         * - contiene solo JMP, LEA e NOP
         *
         * @return true se contiene almeno un'istruzione utile.
         */
        public boolean hasUsefulIntruction() {
            return !instructions.stream().allMatch(in -> in.isJMP() || in.isNop() || in.isUselessLea());
        }

        /**
         * @return L'istruzione con il primo salto incondizionato o istruzione valida.
         */
        public Optional<InstructionInfo> getFirstUsefulInstructionOrJump() {
            // TODO: verifica
            return this.instructions.stream()
                    .filter(i -> !i.isUseless() &&
                                 !i.isConditionalJump())
                    .findFirst();
        }

        /**
         * @return True se contiene l'indirizzo dato in input
         */
        public boolean containsAddress(Address address) {
            return instructions.stream().anyMatch(i -> i.getAddress().equals(address));
        }

        public Optional<Address> getAddressOfNextGroup() {
            return instructions.stream()
                    .filter(InstructionInfo::isJMP)
                    .findFirst()
                    .flatMap(InstructionInfo::getJumpAddress);
        }

        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (var i : instructions) {
                sb.append(i.toString()).append("\n");
            }
            sb.append("--------");
            return sb.toString();
        }

        /**
         * Aggiorna i salti condizionati e restituisce gli indirizzi a cui vanno assegnate le label
         *
         * @return una mappa con indirizzi e nomi delle label da aggiungere.
         */
        public Map<Address, String> updateConditionalJumps() {
            List<InstructionInfo> updatedInstructions = new ArrayList<>();
            Map<Address, String> map = new HashMap<>();
            for (InstructionInfo instruction : instructions) {
                if (instruction.isConditionalJump()) {
                    String label = "Label_" + counterLabel++;
                    var refAddress = instruction.setConditionalJumpAddressString(label);
                    refAddress.ifPresent(value -> map.put(value, label));
                }
                updatedInstructions.add(instruction);
            }
            this.instructions = updatedInstructions;
            return map;
        }
    }
}
