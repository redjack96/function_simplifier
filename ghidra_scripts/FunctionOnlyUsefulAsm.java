// Reorders the instructions of the current function selected and creates a file with the code without NOPs and useless LEAs.
//@author Giacomo Lorenzo Rossi
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.util.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.File;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

// TODO: sostituire gli indirizzi dei salti condizionati con delle label e aggiungerle prima dell'istruzione utile.
public class FunctionOnlyUsefulAsm extends GhidraScript {

    private static final String[] conditionalJumps = {"JAE", "JB", "JBE", "JC", "JE", "JZ", "JG", "JGE", "JL", "JLE",
            "JNA", "JNAE", "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE", "JNL", "JNLE", "JNO", "JNP",
            "JNS", "JNZ", "JO", "JP", "JPE", "JPO", "JS"};

    @Override
    public void run() throws Exception {
        Optional<Function> currentFuncOpt = Optional.ofNullable(getFunctionContaining(currentAddress));
        if (currentFuncOpt.isEmpty()) {
            println("The address at " + currentAddress + " is not in a function");
            return;
        }
        Function function = currentFuncOpt.get();
        printf("Semplifico la funzione %s a indirizzo %s\n", function.getName(), function.getEntryPoint().toString());

        var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);

        // ricavo le istruzioni della funzione corrente.
        List<InstructionInfo> ii = getInstructionsOfFunction(instructions);

        // raggruppo le istruzioni tra un salto e l'altro.
        var groups = groupInstructions(ii);

        // riordino i gruppi in ordine, seguendo i salti
        var orderedGroups = reorderInstructionGroups(groups);

        File f = new File(String.format("%s/Desktop/%s-bytes.txt", System.getProperty("user.home"), function.getName()));
        f.createNewFile();
        println("Creo un file in " + f.getAbsolutePath());

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

    static final class InstructionInfo {
        private final String address;
        private String code;
        private final int numOperands;
        private final List<Object> operandRepresentations = new ArrayList<>();
        private String bytes;
        private final Instruction instruction;

        public InstructionInfo(Instruction i) {
            this.address = i.getAddressString(false, true);
            this.code = i.toString();
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
         * cambia la label del salto. Se l'istruzione non è un salto condizionato non fa nulla
         *
         * @param jumpLabel
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
            return String.format("%s",this.code);
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

        // Non ha solo salti

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
    }
}
